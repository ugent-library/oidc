[![Go Reference](https://pkg.go.dev/badge/github.com/ugent-library/oidc.svg)](https://pkg.go.dev/github.com/ugent-library/oidc)

# ugent-library/oidc

Package oidc aims to provide an easy-to-use way to do OpenID Connect ID token
based authentication in your Go web app.

## Install

```sh
go get -u github.com/ugent-library/oidc
```

## Examples

```go
    oidcAuth, _ := oidc.NewAuth(context.TODO(), oidc.Config{
		URL:          config.OIDC.URL,
		ClientID:     config.OIDC.ID,
		ClientSecret: config.OIDC.Secret,
		RedirectURL:  baseURL + "/auth/oidc",
		CookieName:   "oidc.state",
		CookieSecret: []byte(config.OIDC.CookieSecret),
	})

    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        err := oidcAuth.BeginAuth(w, r)
        if err != nil {
            http.Error(w, "auth failed", http.StatusInternalServerError)
        }
    })

    http.HandleFunc("/auth/oidc", func(w http.ResponseWriter, r *http.Request) {
        claims := oidc.Claims{}
    	err := h.oidcAuth.CompleteAuth(c.Res, c.Req, &claims)
        if err != nil {
            http.Error(w, "auth failed", http.StatusInternalServerError)
    		return
    	}

        // handle successful login
    })
```
