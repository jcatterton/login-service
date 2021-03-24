package model

import "time"

type Log struct {
	AppName   string    `json:"appName" bson:"appName"`
	Event     string    `json:"event" bson:"event"`
	Message   string    `json:"message" bson:"message"`
	IsError   bool      `json:"isError" bson:"isError"`
	TimeStamp time.Time `json:"timeStamp" bson:"timeStamp"`
}
