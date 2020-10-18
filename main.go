package main

import (
	"fmt"
	"log"

	"github.com/cvhariharan/cli-auth/auth"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	code "github.com/nirasan/go-oauth-pkce-code-verifier"
)

const APPNAME = "AUTH"

type Config struct {
	ClientId     string `required:"true"`
	ClientSecret string `required:"true"`
	RedirectPort string `required:"true"`
	ConfigUrl    string `required:"true"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	var config Config
	err = envconfig.Process(APPNAME, &config)
	if err != nil {
		log.Fatal(err.Error())
	}

	oa, err := auth.NewOAuthFlow(config.ConfigUrl, config.ClientId, config.ClientSecret, config.RedirectPort, "ryafdagfaj")
	if err != nil {
		log.Println(err)
	}

	// PKCE flow
	codeVerifier, _ := code.CreateCodeVerifier()
	codeChallenge := codeVerifier.CodeChallengeS256()
	token, err := oa.ObtainAccessToken(codeChallenge, auth.S256)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token)
}
