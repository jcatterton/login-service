package main

import (
	"github.com/sirupsen/logrus"

	"login-service/pkg/api"
)

func main() {
	if err := api.ListenAndServe(); err != nil {
		logrus.WithError(err).Fatal("Failed to start API server")
	}
}
