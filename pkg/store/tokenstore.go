package store

import "errors"

var (
	ErrTokenNotFound = errors.New("Token not found for the user")
)

type AuthTokenStore interface {
	GetAuthToken() (string, error)
	SetAuthToken(token string) error
}

type AuthToken struct {
	Token string
}

func NewAuthTokenStore() AuthTokenStore {
	return &AuthToken{}
}

func (a *AuthToken) GetAuthToken() (string, error) {
	val := a.Token
	if val == "" {
		return val, ErrTokenNotFound
	}
	return val, nil
}

func (a *AuthToken) SetAuthToken(token string) error {
	a.Token = token
	return nil
}
