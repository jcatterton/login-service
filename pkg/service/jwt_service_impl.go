package service

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"login-service/model"
	"time"
)

type TokenService struct {
	SigningMethod jwt.SigningMethod
	Issuer        string
	Signature     []byte
}

func (ts *TokenService) GenerateToken(username string) (string, error) {
	t := time.Now()
	midnight := time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())

	claims := model.CustomClaim{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: midnight.UTC().Unix(),
			Issuer:    ts.Issuer,
		},
	}

	token, err := jwt.NewWithClaims(ts.SigningMethod, claims).SignedString(ts.Signature)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (ts *TokenService) ValidateToken(token string) (string, error) {
	parsedToken, err := jwt.ParseWithClaims(
		token,
		&model.CustomClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return ts.Signature, nil
		},
	)
	if err != nil {
		return "", err
	}

	claims, ok := parsedToken.Claims.(*model.CustomClaim)
	if !ok {
		return "", errors.New("unable to parse claims")
	}

	if claims.ExpiresAt < time.Now().UTC().Unix() {
		return "", errors.New("token is expired")
	}

	return claims.Username, nil
}
