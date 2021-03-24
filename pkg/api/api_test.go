package api

import (
	"errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"login-service/model"
	"login-service/pkg/testhelper/mocks"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApi_CheckHealth_ShouldReturn500IfUnableToConnecteToDatabase(t *testing.T) {
	handler := &mocks.DbHandler{}
	handler.On("Ping", mock.Anything).Return(errors.New("test"))

	req, err := http.NewRequest(http.MethodGet, "/health", nil)
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(checkHealth(handler))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 500, recorder.Code)
}

func TestApi_CheckHealth_ShouldReturn200OnSuccess(t *testing.T) {
	handler := &mocks.DbHandler{}
	handler.On("Ping", mock.Anything).Return(nil)

	req, err := http.NewRequest(http.MethodGet, "/health", nil)
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(checkHealth(handler))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 200, recorder.Code)
}

func TestApi_HandleLoginRequest_ShouldReturn400IfUnableToDecodeRequestBody(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	req, err := http.NewRequest(http.MethodPost, "/login", ioutil.NopCloser(strings.NewReader("")))
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(handleLoginRequest(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 400, recorder.Code)
}

func TestApi_HandleLoginRequest_ShouldReturn401IfUnableToFindUser(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	handler.On("GetUser", mock.Anything, mock.Anything).Return(nil, errors.New("mongo: no documents in result"))
	producer.On("Produce", mock.Anything, mock.Anything, mock.Anything)

	req, err := http.NewRequest(http.MethodPost, "/login", ioutil.NopCloser(strings.NewReader(`{"username": "test", "password": "test"}`)))
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(handleLoginRequest(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 401, recorder.Code)
}

func TestApi_HandleLoginRequest_ShouldReturn500IfErrorSearchingDatabase(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	handler.On("GetUser", mock.Anything, mock.Anything).Return(nil, errors.New("test"))
	producer.On("Produce", mock.Anything, mock.Anything, mock.Anything)

	req, err := http.NewRequest(http.MethodPost, "/login", ioutil.NopCloser(strings.NewReader(`{"username": "test", "password": "test"}`)))
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(handleLoginRequest(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 500, recorder.Code)
}

func TestApi_HandleLoginRequest_ShouldReturn401IfRequestPasswordDoesNotMatchUserPasswordHash(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	mockPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	require.Nil(t, err)
	mockUser := model.User{
		Username:     "test",
		PasswordHash: mockPassword,
	}

	handler.On("GetUser", mock.Anything, mock.Anything).Return(&mockUser, nil)
	producer.On("Produce", mock.Anything, mock.Anything, mock.Anything)

	req, err := http.NewRequest(http.MethodPost, "/login", ioutil.NopCloser(strings.NewReader(`{"username": "test", "password": "test"}`)))
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(handleLoginRequest(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 401, recorder.Code)
}

func TestApi_HandleLoginRequest_ShouldReturn500IfErrorOccursGeneratingToken(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	mockPassword, err := bcrypt.GenerateFromPassword([]byte("test"), bcrypt.DefaultCost)
	require.Nil(t, err)
	mockUser := model.User{
		Username:     "test",
		PasswordHash: mockPassword,
	}

	handler.On("GetUser", mock.Anything, mock.Anything).Return(&mockUser, nil)
	service.On("GenerateToken", mock.Anything).Return("", errors.New("test"))

	req, err := http.NewRequest(http.MethodPost, "/login", ioutil.NopCloser(strings.NewReader(`{"username": "test", "password": "test"}`)))
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(handleLoginRequest(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 500, recorder.Code)
}

func TestApi_HandleLoginRequest_ShouldReturn200OnSuccess(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	mockPassword, err := bcrypt.GenerateFromPassword([]byte("test"), bcrypt.DefaultCost)
	require.Nil(t, err)
	mockUser := model.User{
		Username:     "test",
		PasswordHash: mockPassword,
	}

	handler.On("GetUser", mock.Anything, mock.Anything).Return(&mockUser, nil)
	service.On("GenerateToken", mock.Anything).Return("test", nil)

	req, err := http.NewRequest(http.MethodPost, "/login", ioutil.NopCloser(strings.NewReader(`{"username": "test", "password": "test"}`)))
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(handleLoginRequest(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 200, recorder.Code)
}

func TestApi_ValidateToken_ShouldReturn400IfNoAuthorizationHeaderIsFound(t *testing.T) {
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	req, err := http.NewRequest(http.MethodPost, "/token", nil)
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(validateToken(service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 400, recorder.Code)
}

func TestApi_ValidateToken_ShouldReturn400IfAuthorizationHeaderIsMalformed(t *testing.T) {
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	req, err := http.NewRequest(http.MethodPost, "/token", nil)
	require.Nil(t, err)

	req.Header.Add("Authorization", "test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(validateToken(service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 400, recorder.Code)
}

func TestApi_ValidateToken_ShouldReturn500IfErrorValidatingToken(t *testing.T) {
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	service.On("ValidateToken", mock.Anything).Return("", errors.New("test"))
	producer.On("Produce", mock.Anything, mock.Anything, mock.Anything)

	req, err := http.NewRequest(http.MethodPost, "/token", nil)
	require.Nil(t, err)

	req.Header.Add("Authorization", "Bearer test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(validateToken(service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 500, recorder.Code)
}

func TestApi_ValidateToken_ShouldReturn200OnSuccess(t *testing.T) {
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	service.On("ValidateToken", mock.Anything).Return("test", nil)

	req, err := http.NewRequest(http.MethodPost, "/token", nil)
	require.Nil(t, err)

	req.Header.Add("Authorization", "Bearer test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(validateToken(service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 200, recorder.Code)
}

func TestApi_NewUser_ShouldReturn400IfNoAuthorizationHeaderIsFound(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	req, err := http.NewRequest(http.MethodPost, "/user", nil)
	require.Nil(t, err)

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(newUser(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 400, recorder.Code)
}

func TestApi_NewUser_ShouldReturn400IfAuthorizationheaderIsMalformed(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	req, err := http.NewRequest(http.MethodPost, "/user", nil)
	require.Nil(t, err)

	req.Header.Add("Authorization", "test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(newUser(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 400, recorder.Code)
}

func TestApi_NewUser_ShouldReturn500IfErrorValidatingToken(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	service.On("ValidateToken", mock.Anything).Return("", errors.New("test"))
	producer.On("Produce", mock.Anything, mock.Anything, mock.Anything)

	req, err := http.NewRequest(http.MethodPost, "/user", nil)
	require.Nil(t, err)

	req.Header.Add("Authorization", "Bearer test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(newUser(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 500, recorder.Code)
}

func TestApi_NewUser_ShouldReturn400IfUnableToDecodeRequestBody(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	service.On("ValidateToken", mock.Anything).Return("test", nil)

	req, err := http.NewRequest(http.MethodPost, "/user", ioutil.NopCloser(strings.NewReader("")))
	require.Nil(t, err)

	req.Header.Add("Authorization", "Bearer test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(newUser(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 400, recorder.Code)
}

func TestApi_NewUser_ShouldReturn400IfRequestUsernameIsEmpty(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	service.On("ValidateToken", mock.Anything).Return("test", nil)

	req, err := http.NewRequest(http.MethodPost, "/user", ioutil.NopCloser(strings.NewReader(`{"username": ""}`)))
	require.Nil(t, err)

	req.Header.Add("Authorization", "Bearer test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(newUser(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 400, recorder.Code)
}

func TestApi_NewUser_ShouldReturn400IfRequestPasswordIsEmpty(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	service.On("ValidateToken", mock.Anything).Return("test", nil)

	req, err := http.NewRequest(http.MethodPost, "/user", ioutil.NopCloser(strings.NewReader(`{"username": "test", "password": ""}`)))
	require.Nil(t, err)

	req.Header.Add("Authorization", "Bearer test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(newUser(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 400, recorder.Code)
}

func TestApi_NewUser_ShouldReturn500IfErrorCreatingUser(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	handler.On("AddUser", mock.Anything, mock.Anything).Return(errors.New("test"))
	service.On("ValidateToken", mock.Anything).Return("test", nil)

	req, err := http.NewRequest(http.MethodPost, "/user", ioutil.NopCloser(strings.NewReader(`{"username": "test", "password": "test"}`)))
	require.Nil(t, err)

	req.Header.Add("Authorization", "Bearer test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(newUser(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 500, recorder.Code)
}

func TestApi_NewUser_ShouldReturn200OnSuccess(t *testing.T) {
	handler := &mocks.DbHandler{}
	service := &mocks.JWTService{}
	producer := &mocks.KafkaProducer{}

	handler.On("AddUser", mock.Anything, mock.Anything).Return(nil)
	service.On("ValidateToken", mock.Anything).Return("test", nil)
	producer.On("Produce", mock.Anything, mock.Anything, mock.Anything)

	req, err := http.NewRequest(http.MethodPost, "/user", ioutil.NopCloser(strings.NewReader(`{"username": "test", "password": "test"}`)))
	require.Nil(t, err)

	req.Header.Add("Authorization", "Bearer test")

	recorder := httptest.NewRecorder()
	httpHandler := http.HandlerFunc(newUser(handler, service, producer))
	httpHandler.ServeHTTP(recorder, req)
	require.Equal(t, 200, recorder.Code)
}
