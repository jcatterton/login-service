package dao

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"strings"

	"login-service/model"
)

type MongoClient struct {
	Client         *mongo.Client
	Database       string
	UserCollection string
}

func (c *MongoClient) Ping(ctx context.Context) error {
	return c.Client.Ping(ctx, readpref.Primary())
}

func (c *MongoClient) AddUser(ctx context.Context, user model.User) error {
	result, err := c.getCollection().InsertOne(ctx, user)
	if err != nil {
		if strings.Contains(err.Error(), "username dup key") {
			return errors.New("user with that username already exists")
		}
		return err
	} else if result.InsertedID != nil {
		return nil
	}
	return errors.New("no user inserted")
}

func (c *MongoClient) GetUser(ctx context.Context, username string) (*model.User, error) {
	result := c.getCollection().FindOne(ctx, map[string]string{"username": username})
	if result.Err() != nil {
		return nil, result.Err()
	}

	var user model.User
	if err := result.Decode(&user); err != nil {
		return nil, errors.New("error decoding result")
	}

	return &user, nil
}

func (c *MongoClient) getCollection() *mongo.Collection {
	return c.Client.Database(c.Database).Collection(c.UserCollection)
}
