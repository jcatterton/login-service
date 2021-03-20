package model

type User struct {
	Username     string `json:"username" bson:"username"`
	PasswordHash []byte `json:"passwordHash" bson:"passwordHash"`
}

type NewUserRequest struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}

type GetUserRequest struct {
	Username string `json:"username" bson:"password"`
}
