// Package oidc aims to provide an easy-to-use way to do OpenID Connect ID token
// based authentication in your Go web app.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

type Config struct {
	URL              string
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	AdditionalScopes []string
	CookieName       string
	CookieSecret     []byte
}

type Auth struct {
	oauthConfig   *oauth2.Config
	tokenVerifier *oidc.IDTokenVerifier
	secureCookie  *securecookie.SecureCookie
	cookieName    string
}

func NewAuth(ctx context.Context, c Config) (*Auth, error) {
	oidcProvider, err := oidc.NewProvider(ctx, c.URL)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}

	// configure an oidc aware oauth2 client
	oauthConfig := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	if c.AdditionalScopes != nil {
		oauthConfig.Scopes = append(oauthConfig.Scopes, c.AdditionalScopes...)
	} else {
		oauthConfig.Scopes = append(oauthConfig.Scopes, "profile")
	}

	tokenVerifier := oidcProvider.Verifier(&oidc.Config{ClientID: c.ClientID})

	auth := &Auth{
		oauthConfig:   oauthConfig,
		tokenVerifier: tokenVerifier,
		secureCookie:  securecookie.New(c.CookieSecret, nil),
		cookieName:    c.CookieName,
	}

	if auth.cookieName == "" {
		auth.cookieName = "oidc.state"
	}

	return auth, nil
}

func (a *Auth) BeginAuth(w http.ResponseWriter, r *http.Request) error {
	state, err := newState()
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	h, err := a.secureCookie.Encode(a.cookieName, state)
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    h,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	})

	http.Redirect(w, r, a.oauthConfig.AuthCodeURL(state), http.StatusTemporaryRedirect)

	return nil
}

func (a *Auth) CompleteAuth(w http.ResponseWriter, r *http.Request, claims any) error {
	cookie, err := r.Cookie(a.cookieName)
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	var state string
	if err = a.secureCookie.Decode(a.cookieName, cookie.Value, &state); err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	// delete cookie
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		MaxAge:   -1,
	})

	if r.URL.Query().Get("state") != state {
		return errors.New("oidc: invalid state parameter")
	}

	oauthToken, err := a.oauthConfig.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	// extract id token from oauth2 token
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		return errors.New("oidc: id token missing")
	}

	// verify id token
	idToken, err := a.tokenVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	return idToken.Claims(claims)
}

func newState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(b)

	return state, nil
}