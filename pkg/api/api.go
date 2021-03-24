package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"login-service/pkg/producer"
	"login-service/pkg/service"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"login-service/model"
	"login-service/pkg/dao"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

func ListenAndServe() error {
	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type"})
	origins := handlers.AllowedOrigins([]string{"*"})
	methods := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS", "DELETE"})

	router, err := route()
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler:      handlers.CORS(headers, origins, methods)(router),
		Addr:         ":8003",
		WriteTimeout: 20 * time.Second,
		ReadTimeout:  20 * time.Second,
	}
	shutdownGracefully(server)

	logrus.Info(fmt.Sprintf("Server is listening on port %v", server.Addr))
	return server.ListenAndServe()
}

func route() (*mux.Router, error) {
	r := mux.NewRouter()

	dbClient, err := mongo.Connect(context.Background(), options.Client().ApplyURI(os.Getenv("MONGO_URI")))
	if err != nil {
		logrus.WithError(err).Error("Error creating database client")
		return nil, err
	}

	dbHandler := dao.MongoClient{
		Client:         dbClient,
		Database:       "db",
		UserCollection: "users",
	}

	jwtService := service.TokenService{
		SigningMethod: jwt.SigningMethodHS256,
		Issuer:        "jcat-login-service",
		Signature:     []byte(os.Getenv("SIGNATURE")),
	}

	p, err := producer.CreateProducer(os.Getenv("BROKER"), os.Getenv("TOPIC"))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create producer")
		return nil, err
	}

	r.HandleFunc("/health", checkHealth(&dbHandler)).Methods(http.MethodGet)
	r.HandleFunc("/login", handleLoginRequest(&dbHandler, &jwtService, p)).Methods(http.MethodPost)
	r.HandleFunc("/token", validateToken(&jwtService, p)).Methods(http.MethodPost)
	r.HandleFunc("/user", newUser(&dbHandler, &jwtService, p)).Methods(http.MethodPost)

	return r, nil
}

func checkHealth(handler dao.DbHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer closeRequestBody(r)
		if err := handler.Ping(r.Context()); err != nil {
			respondWithError(w, http.StatusInternalServerError, "API is healthy, but unable to reach database")
			return
		}
		respondWithSuccess(w, http.StatusOK, "API is healthy and connected to database")
		return
	}
}

func handleLoginRequest(handler dao.DbHandler, tokenService service.JWTService, p producer.KafkaProducer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		defer closeRequestBody(r)

		var loginRequest model.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
			logrus.WithError(err).Error("Error decoding request body")
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}

		user, err := handler.GetUser(ctx, loginRequest.Username)
		if err != nil {
			if err.Error() == "mongo: no documents in result" {
				err = errors.New("authentication failed")
				logrus.WithError(err).Error("Unable to authenticate user")
				respondWithError(w, http.StatusUnauthorized, "Unable to authenticate user")
			} else {
				logrus.WithError(err).Error("Error retrieving user from database")
				respondWithError(w, http.StatusInternalServerError, err.Error())
			}
			p.Produce("authentication_failure", fmt.Sprintf("authentication failed for user '%v' - user not found", loginRequest.Username), true)
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(loginRequest.Password)); err != nil {
			err := errors.New("authentication failed")
			logrus.WithError(err).Error("Unable to authenticate user")
			respondWithError(w, http.StatusUnauthorized, "Unable to authenticate user")
			p.Produce("authentication_failure", fmt.Sprintf("authentication failed for user '%v' - invalid credentials", loginRequest.Username), true)
			return
		}

		token, err := tokenService.GenerateToken(user.Username)
		if err != nil {
			logrus.WithError(err).Error("Error generating token")
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}

		logrus.Info("Authentication successful")
		respondWithSuccess(w, http.StatusOK, &token)
		return
	}
}

func validateToken(tokenService service.JWTService, p producer.KafkaProducer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer closeRequestBody(r)

		tokenHeader := r.Header.Get("Authorization")
		if tokenHeader == "" {
			logrus.Error("No authorization header found")
			respondWithError(w, http.StatusBadRequest, "No authorization header found")
			return
		} else if (len(tokenHeader) >= 7 && tokenHeader[:7] != "Bearer ") || len(strings.Split(tokenHeader, " ")) != 2 {
			logrus.Error("Authorization header must be in format 'Bearer <token>'")
			respondWithError(w, http.StatusBadRequest, "Authorization header must be in format 'Bearer <token>'")
			return
		}
		token := strings.Split(tokenHeader, " ")[1]

		username, err := tokenService.ValidateToken(token)
		if err != nil {
			logrus.WithError(err).Error("Error validating token")
			respondWithError(w, http.StatusInternalServerError, err.Error())
			p.Produce("authentication_failure", fmt.Sprintf("authentication failed - invalid token"), true)
			return
		}

		logrus.WithField("username", username).Info("Token successfully validated")
		respondWithSuccess(w, http.StatusOK, fmt.Sprintf("Token validated for user '%v'", username))
		return
	}
}

func newUser(handler dao.DbHandler, tokenService service.JWTService, p producer.KafkaProducer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		defer closeRequestBody(r)

		tokenHeader := r.Header.Get("Authorization")
		if tokenHeader == "" {
			logrus.Error("No authorization header found")
			respondWithError(w, http.StatusBadRequest, "No authorization header found")
			return
		} else if (len(tokenHeader) >= 7 && tokenHeader[:7] != "Bearer ") || len(strings.Split(tokenHeader, " ")) != 2 {
			logrus.Error("Authorization header must be in format 'Bearer <token>'")
			respondWithError(w, http.StatusBadRequest, "Authorization header must be in format 'Bearer <token>'")
			return
		}
		token := strings.Split(tokenHeader, " ")[1]

		_, err := tokenService.ValidateToken(token)
		if err != nil {
			logrus.WithError(err).Error("Error validating token")
			respondWithError(w, http.StatusInternalServerError, err.Error())
			p.Produce("authentication_failure", "authentication failed - invalid token", true)
			return
		}

		var userRequest model.NewUserRequest
		if err := json.NewDecoder(r.Body).Decode(&userRequest); err != nil {
			logrus.WithError(err).Error("Error decoding request body")
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}

		if userRequest.Username == "" {
			err := errors.New("username is required")
			logrus.WithError(err).Error("Error creating user")
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		} else if userRequest.Password == "" {
			err := errors.New("password is required")
			logrus.WithError(err).Error("Error creating user")
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}

		hashPassword, err := bcrypt.GenerateFromPassword([]byte(userRequest.Password), bcrypt.DefaultCost)
		if err != nil {
			logrus.WithError(err).Error("Error generating hash from given password")
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}

		user := model.User{
			Username:     userRequest.Username,
			PasswordHash: hashPassword,
		}

		if err := handler.AddUser(ctx, user); err != nil {
			logrus.WithError(err).Error("Error adding user to database")
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}

		logrus.Info("User successfully created")
		respondWithSuccess(w, http.StatusOK, "User successfully created")
		p.Produce("user_created", fmt.Sprintf("user '%v' created succesfully", user.Username), false)
		return
	}
}

func shutdownGracefully(server *http.Server) {
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt)
		<-signals

		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(c); err != nil {
			logrus.WithError(err).Error("Error shutting down server")
		}

		<-c.Done()
		os.Exit(0)
	}()
}

func respondWithSuccess(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if body == nil {
		logrus.Error("Body is nil, unable to write response")
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logrus.WithError(err).Error("Error encoding response")
	}
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if message == "" {
		logrus.Error("Body is nil, unable to write response")
		return
	}
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		logrus.WithError(err).Error("Error encoding response")
	}
}

func closeRequestBody(req *http.Request) {
	if req.Body == nil {
		return
	}
	if err := req.Body.Close(); err != nil {
		logrus.WithError(err).Error("Error closing request body")
		return
	}
	return
}
