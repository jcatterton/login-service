package service

type JWTService interface {
	GenerateToken(username string) (string, error)
	ValidateToken(token string) (string, error)
}
