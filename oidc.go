package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	ErrTokenExpired = errors.New("ID Token expired")
	// The requested resource is not supported by the provider.
	ErrNotSupported = errors.New("endpoint not supported")
)

// ScopeOpenID is the mandatory scope for all OpenID Connect OAuth2 requests.
const ScopeOpenID = "openid"

// IDTokenVerifier provides some verification on a raw ID Token, such as verifing the
// JWT signatures or expiration.
type IDTokenVerifier interface {
	// Verify verifies some property of the JWT and returns the associated payload.
	Verify(rawIDToken string) (payload []byte, err error)
}

// Provider contains a subset of the OpenID Connect provider metadata.
//
// Issuer, AuthURL, TokenURL, and JWKSURL are all manditory fields.
type Provider struct {
	Issuer          string   `json:"issuer"`
	AuthURL         string   `json:"authorization_endpoint"`
	TokenURL        string   `json:"token_endpoint"`
	JWKSURL         string   `json:"jwks_uri"`
	UserInfoURL     string   `json:"userinfo_endpoint"`
	Scopes          []string `json:"scopes_supported"`
	ClaimsSupported []string `json:"claims_supported"`
}

// NewProvider uses the OpenID Connect disovery mechanism to construct a Provider.
func NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to parse issuer as URL: %v", err)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/.well-known/openid-configuration"

	cli := contextClient(ctx)
	resp, err := cli.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var p Provider
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider at well known config: %v", err)
	}
	if p.Issuer != issuer {
		return nil, fmt.Errorf("oidc: issuer did not match the issuer field returned by provider metadata")
	}
	return &p, nil
}

// Endpoint returns the OAuth2 auth and token endpoints for the given provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{AuthURL: p.AuthURL, TokenURL: p.TokenURL}
}

// UserInfo represents the OpenID Connect userinfo claims.
type UserInfo struct {
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	// Optionally contains extra claims.
	raw map[string]interface{}
}

// Extra returns additional claims returned by the server.
func (u *UserInfo) Extra(key string) interface{} {
	if u.raw != nil {
		return u.raw[key]
	}
	return nil
}

// UserInfo uses the token source to query the provider's user info endpoint.
func (p *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*UserInfo, error) {
	if p.UserInfoURL == "" {
		return nil, ErrNotSupported
	}
	cli := oauth2.NewClient(ctx, tokenSource)
	resp, err := cli.Get(p.UserInfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode userinfo: %v", err)
	}
	// raw claims do not get error checks
	json.Unmarshal(body, &userInfo.raw)
	return &userInfo, nil
}

// Verifier returns an IDTokenVerifier that uses the provider's key set to verify JWTs.
//
// The verifier queries the provider to update keys when a signature cannot be verified by the
// set of keys cached from the previous request.
//
// If the token has expired, the verifier will refuse to process it.
func (p *Provider) Verifier(ctx context.Context) IDTokenVerifier {
	return issuerVerifier{
		issuer: p.Issuer,
		tokenVerifier: expVerifier{
			tokenVerifier: newRemoteKeySet(ctx, p.JWKSURL),
		},
	}
}

// This method is internal to golang.org/x/oauth2. Just copy it.
func contextClient(ctx context.Context) *http.Client {
	if ctx != nil {
		if hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
			return hc
		}
	}
	return http.DefaultClient
}

// expVerifier ensures an ID Token has not expired.
type expVerifier struct {
	tokenVerifier IDTokenVerifier
}

func (e expVerifier) Verify(rawIDToken string) (payload []byte, err error) {
	payload, err = e.tokenVerifier.Verify(rawIDToken)
	if err != nil {
		return nil, err
	}
	var token struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("oidc: failed to unmarshal expiration: %v", err)
	}
	if time.Unix(token.Exp, 0).Before(time.Now().Round(time.Second)) {
		return nil, ErrTokenExpired
	}
	return payload, nil
}

type issuerVerifier struct {
	issuer        string
	tokenVerifier IDTokenVerifier
}

func (i issuerVerifier) Verify(rawIDToken string) (payload []byte, err error) {
	payload, err = i.tokenVerifier.Verify(rawIDToken)
	if err != nil {
		return nil, err
	}
	var token struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("oidc: failed to unmarshal issuer: %v", err)
	}
	if i.issuer != token.Issuer {
		return nil, fmt.Errorf("oidc: iss field did not match provider issuer")
	}
	return payload, nil
}
