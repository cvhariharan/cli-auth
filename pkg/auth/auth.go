package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"log"

	"github.com/coreos/go-oidc"
	"github.com/cvhariharan/cli-auth/pkg/store"
	browser "github.com/cvhariharan/cli-auth/pkg/utils"
	"golang.org/x/oauth2"
)

const (
	S256  = "S256"
	PLAIN = "plain"
)

var successHtml = `<html><body onload="javascript:window.open('','_self').close();"></body></html>`

var authTokenStore = store.NewAuthTokenStore()

type OAuthFlow struct {
	Provider      *oidc.Provider
	ClientID      string
	ClientSecret  string
	Scopes        []string
	RedirectURL   string
	OpenInBrowser bool
	State         string
	port          string
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
func (o *OAuthFlow) ObtainAccessToken(codeChallenge, challengeMethod string) (*oauth2.Token, error) {
	log.Println("Obtain token")
	oauth2Config := oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  o.RedirectURL,
		Endpoint:     o.Provider.Endpoint(),
		Scopes:       o.Scopes,
	}

	var token *oauth2.Token
	log.Println(o.RedirectURL)

	m := http.NewServeMux()

	s := http.Server{Addr: ":7000", Handler: m}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != o.State {
			log.Println("error")
			http.Error(w, "Invalid state", http.StatusBadRequest)
			gracefulShutdown(ctx, &s)
		}

		var err error
		token, err = oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Println(err)
			gracefulShutdown(ctx, &s)
		}

		fmt.Fprint(w, successHtml)
		gracefulShutdown(ctx, &s)
	})

	browser.Open(oauth2Config.AuthCodeURL(o.State, oauth2.SetAuthURLParam("code_challenger", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", challengeMethod)))

	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	return token, nil
}

func gracefulShutdown(ctx context.Context, s *http.Server) {
	go func() {
		time.Sleep(1 * time.Second)
		s.Shutdown(ctx)
	}()
}
