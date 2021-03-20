package model

import "github.com/dgrijalva/jwt-go"

type LoginRequest struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}

type CustomClaim struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
