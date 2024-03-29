package oidc

import (
	"encoding/json"
)

// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims.
type StandardClaims struct {
	Address             *Address `json:"address,omitempty"`
	Birthdate           string   `json:"birthdate,omitempty"`
	Email               string   `json:"email,omitempty"`
	EmailVerified       bool     `json:"email_verified,omitempty"`
	FamilyName          string   `json:"family_name,omitempty"`
	Gender              string   `json:"gender,omitempty"`
	GivenName           string   `json:"given_name,omitempty"`
	Locale              string   `json:"locale,omitempty"`
	MiddleName          string   `json:"middle_name,omitempty"`
	Name                string   `json:"name,omitempty"`
	Nickname            string   `json:"nickname,omitempty"`
	PhoneNumber         string   `json:"phone_number,omitempty"`
	PhoneNumberVerified bool     `json:"phone_number_verified,omitempty"`
	Picture             string   `json:"picture,omitempty"`
	PreferredUsername   string   `json:"preferred_username,omitempty"`
	Profile             string   `json:"profile,omitempty"`
	Subject             string   `json:"sub,omitempty"`
	UpdatedAt           int64    `json:"updated_at,omitempty"`
	Website             string   `json:"website,omitempty"`
	ZoneInfo            string   `json:"zoneinfo,omitempty"`
}

// https://openid.net/specs/openid-connect-core-1_0.html#Address.
type Address struct {
	Country       string `json:"country,omitempty"`
	Formatted     string `json:"formatted,omitempty"`
	Locality      string `json:"locality,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Region        string `json:"region,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
}

type Claims struct {
	StandardClaims
	All map[string]any
}

func (c *Claims) UnmarshalJSON(b []byte) (err error) {
	if err = json.Unmarshal(b, &c.StandardClaims); err != nil {
		return
	}
	if err = json.Unmarshal(b, &c.All); err != nil {
		return
	}
	return
}

func (c *Claims) GetString(key string) string {
	if val, ok := c.All[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}
