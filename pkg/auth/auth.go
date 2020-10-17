package auth

import (
	"context"
	"fmt"
	"net/http"

	"log"

	"github.com/coreos/go-oidc"
	"github.com/cvhariharan/cli-auth/pkg/store"
	browser "github.com/cvhariharan/cli-auth/pkg/utils"
	"golang.org/x/oauth2"
)

var authTokenStore = store.NewAuthTokenStore()

type OAuthFlow struct {
	Provider      *oidc.Provider
	ClientID      string
	ClientSecret  string
	Scopes        []string
	RedirectURL   string
	OpenInBrowser bool
	State         string
}

func NewOAuthFlow(configUrl, clientId, clientSecret, port, state string) (OAuthFlow, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, configUrl)
	if err != nil {
		log.Println(err)
		return OAuthFlow{}, err
	}
	log.Println("Init")
	return OAuthFlow{
		Provider:     provider,
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		RedirectURL:  fmt.Sprintf("http://localhost:%v/success", port),
		State:        state,
	}, nil
}

// ObtainAccessToken opens a browser and follows the oauth flow and returns
// an access token (JWT ID token) if everything goes fine
func (o *OAuthFlow) ObtainAccessToken() (accessToken string, err error) {
	log.Println("Obtain token")
	oauth2Config := oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  o.RedirectURL,
		Endpoint:     o.Provider.Endpoint(),
		Scopes:       o.Scopes,
	}

	// oidcConfig := &oidc.Config{
	// 	ClientID: o.ClientID,
	// }
	// verifier := o.Provider.Verifier(oidcConfig)

	// Check if the auth token is cached, if not redirect to the login page in browser
	token, err := authTokenStore.GetAuthToken()
	if err == store.ErrTokenNotFound {
		// Redirect to browser
		log.Println(oauth2Config.AuthCodeURL(o.State))
		browser.Open(oauth2Config.AuthCodeURL(o.State))
		m := http.NewServeMux()
		s := http.Server{Addr: ":7000", Handler: m}
		m.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {
			ctx := context.Background()
			if r.URL.Query().Get("state") != o.State {
				http.Error(w, "Invalid state", http.StatusBadRequest)
				s.Shutdown(ctx)
			}

			oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
			if err != nil {
				log.Println(err)
				s.Shutdown(ctx)
			}

			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				log.Println("Could not get ID token")
			}

			token = rawIDToken
			log.Println("Token: ", token)

			// Add to token store
			authTokenStore.SetAuthToken(token)
			s.Shutdown(ctx)
		})

		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}

	} else {

		// Valid if token is valid
		log.Println("Already logged in: ", token)
		return token, nil
	}
	return "", nil
}
