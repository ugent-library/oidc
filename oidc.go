// Package oidc aims to provide an easy-to-use way to do OpenID Connect ID token
// based authentication in your Go web app.

// TODO support PKCE
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/ugent-library/crypt"
	"golang.org/x/oauth2"
)

const (
	defaultCookiePrefix = "oidc."
	defaultCookieMaxAge = time.Hour
)

type Config struct {
	IssuerURL        string
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	AdditionalScopes []string
	CookieInsecure   bool
	CookieMaxAge     time.Duration
	CookieSecret     []byte
	CookieHashSecret []byte
	CookiePrefix     string
}

type Auth struct {
	oauthConfig    *oauth2.Config
	tokenVerifier  *oidc.IDTokenVerifier
	cookies        *securecookie.SecureCookie
	cookieInsecure bool
	cookieMaxAge   time.Duration
	stateCookie    string
	nonceCookie    string
}

func NewAuth(ctx context.Context, c Config) (*Auth, error) {
	if c.CookiePrefix == "" {
		c.CookiePrefix = defaultCookiePrefix
	}
	if c.CookieMaxAge == 0 {
		c.CookieMaxAge = defaultCookieMaxAge
	}

	oidcProvider, err := oidc.NewProvider(ctx, c.IssuerURL)
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
	}

	tokenVerifier := oidcProvider.Verifier(&oidc.Config{ClientID: c.ClientID})

	auth := &Auth{
		oauthConfig:    oauthConfig,
		tokenVerifier:  tokenVerifier,
		cookies:        securecookie.New(c.CookieHashSecret, c.CookieSecret),
		cookieInsecure: c.CookieInsecure,
		cookieMaxAge:   c.CookieMaxAge,
		stateCookie:    c.CookiePrefix + "state",
		nonceCookie:    c.CookiePrefix + "nonce",
	}

	return auth, nil
}

func (a *Auth) BeginAuth(w http.ResponseWriter, r *http.Request) error {
	state, err := crypt.RandomString(32)
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}
	nonce, err := crypt.RandomString(32)
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	if err := a.setAuthCookie(w, a.stateCookie, state); err != nil {
		return err
	}
	if err := a.setAuthCookie(w, a.nonceCookie, nonce); err != nil {
		return err
	}

	authURL := a.oauthConfig.AuthCodeURL(state, oidc.Nonce(nonce))

	http.Redirect(w, r, authURL, http.StatusFound)

	return nil
}

func (a *Auth) CompleteAuth(w http.ResponseWriter, r *http.Request, claims any) error {
	state, err := a.getAuthCookie(r, a.stateCookie)
	if err != nil {
		return err
	}
	nonce, err := a.getAuthCookie(r, a.nonceCookie)
	if err != nil {
		return err
	}

	// check state param
	if r.URL.Query().Get("state") != state {
		return errors.New("oidc: invalid state")
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
	if idToken.Nonce != nonce {
		return errors.New("oidc: invalid nonce")
	}

	return idToken.Claims(claims)
}

func (a *Auth) setAuthCookie(w http.ResponseWriter, name, val string) error {
	v, err := a.cookies.Encode(name, val)
	if err != nil {
		return fmt.Errorf("oidc: can't encode cookie %s: %w", name, err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    v,
		Path:     "/",
		Expires:  time.Now().Add(a.cookieMaxAge),
		HttpOnly: true,
		Secure:   !a.cookieInsecure,
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

func (a *Auth) getAuthCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", fmt.Errorf("oidc: can't get cookie %s: %w", name, err)
	}
	var val string
	if err := a.cookies.Decode(name, cookie.Value, &val); err != nil {
		return "", fmt.Errorf("oidc: can't decode cookie %s: %w", name, err)
	}
	return val, nil
}
