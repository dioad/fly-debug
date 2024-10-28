package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/auth0/go-jwt-middleware/v2/validator"
	"golang.org/x/oauth2"

	"github.com/dioad/net/http/authz/jwt"
	"github.com/dioad/net/oidc"
	"github.com/dioad/net/oidc/flyio"
)

type DebugStruct struct {
	DecodedToken interface{} `json:",omitempty"`
	Error        string      `json:",omitempty"`
}

func FlyValidator() (jwt.TokenValidator, error) {
	config := []oidc.ValidatorConfig{
		{
			EndpointConfig: oidc.EndpointConfig{
				URL: "https://oidc.fly.io/personal",
			},
			Audiences: []string{"account"},
		},
	}

	customClaims := func() validator.CustomClaims { return &oidc.IntrospectionResponse{} }

	v, err := oidc.NewMultiValidatorFromConfig(config, validator.WithCustomClaims(customClaims))
	if err != nil {
		return nil, fmt.Errorf("error creating validator: %w", err)
	}

	return v, nil
}

func FlyDebug() http.HandlerFunc {
	v, err := FlyValidator()
	if err != nil {
		slog.Error("error creating validator", "error", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var token *oauth2.Token
		tokenSource := flyio.NewTokenSource()

		token, err = tokenSource.Token()

		o := DebugStruct{}

		if err != nil {
			slog.Error("error getting token", "error", err)
			o.Error = err.Error()
		}
		if token != nil {
			o.DecodedToken, err = v.ValidateToken(r.Context(), token.AccessToken)
		}

		outputBytes, _ := json.Marshal(o)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(outputBytes)
	}
}

func main() {

	server := http.Server{}

	m := http.NewServeMux()
	m.HandleFunc("GET /debug/fly-token", FlyDebug())

	server.Handler = m
	server.Addr = ":8080"
	err := server.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error("error calling ListenAndServe", "error", err)
	}
}
