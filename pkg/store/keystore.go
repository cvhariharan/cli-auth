package store

import (
	"log"

	"github.com/zalando/go-keyring"
)

const service = "cli-auth"

func Set(username, value string) error {
	return keyring.Set(service, username, value)
}

func Get(username string) (string, error) {
	secret, err := keyring.Get(service, username)
	if err != nil {
		log.Println(err)
		return "", err
	}
	return secret, nil
}
