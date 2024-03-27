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
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	URL              string
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	AdditionalScopes []string
	CookiePrefix     string
}

type Auth struct {
	oauthConfig     *oauth2.Config
	tokenVerifier   *oidc.IDTokenVerifier
	stateCookieName string
	nonceCookieName string
}

func NewAuth(ctx context.Context, c Config) (*Auth, error) {
	if c.CookiePrefix == "" {
		c.CookiePrefix = "oidc."
	}

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
		oauthConfig:     oauthConfig,
		tokenVerifier:   tokenVerifier,
		stateCookieName: c.CookiePrefix + "state",
		nonceCookieName: c.CookiePrefix + "nonce",
	}

	return auth, nil
}

func (a *Auth) BeginAuth(w http.ResponseWriter, r *http.Request) error {
	state, err := newRand()
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	nonce, err := newRand()
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     a.stateCookieName,
		Value:    state,
		Path:     "/",
		Secure:   r.TLS != nil,
		HttpOnly: true,
		MaxAge:   int(time.Hour.Seconds()),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     a.nonceCookieName,
		Value:    nonce,
		Path:     "/",
		Secure:   r.TLS != nil,
		HttpOnly: true,
		MaxAge:   int(time.Hour.Seconds()),
	})

	authURL := a.oauthConfig.AuthCodeURL(state, oidc.Nonce(nonce))

	http.Redirect(w, r, authURL, http.StatusFound)

	return nil
}

func (a *Auth) CompleteAuth(w http.ResponseWriter, r *http.Request, claims any) error {
	stateCookie, err := r.Cookie(a.stateCookieName)
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	nonceCookie, err := r.Cookie(a.nonceCookieName)
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	// check state param
	if r.URL.Query().Get("state") != stateCookie.Value {
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

	// check nonce
	if idToken.Nonce != nonceCookie.Value {
		return errors.New("oidc: invalid nonce")
	}

	return idToken.Claims(claims)
}

func newRand() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
