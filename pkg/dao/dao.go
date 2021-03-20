package dao

import (
	"context"
	"login-service/model"
)

type DbHandler interface {
	Ping(ctx context.Context) error
	AddUser(ctx context.Context, user model.User) error
	GetUser(ctx context.Context, username string) (*model.User, error)
}
