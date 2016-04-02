package oidc

import (
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
)

// Nonce returns an auth code option which requires the ID Token created by the
// OpenID Connect provider to contain the specified nonce.
func Nonce(nonce string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("nonce", nonce)
}

// NonceSource represents a source which can verify a nonce is valid and has not
// been claimed before.
type NonceSource interface {
	ClaimNonce(nonce string) error
}

// NonceVerifier provides nonce verification to an existing IDTokenVerifier.
func NonceVerifier(verifier IDTokenVerifier, source NonceSource) IDTokenVerifier {
	return nonceVerifier{verifier, source}
}

type nonceVerifier struct {
	tokenVerifier IDTokenVerifier
	nonceSource   NonceSource
}

func (n nonceVerifier) Verify(rawIDToken string) (payload []byte, err error) {
	payload, err = n.tokenVerifier.Verify(rawIDToken)
	if err != nil {
		return nil, err
	}
	var token struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("oidc: failed to unmarshal nonce: %v", err)
	}
	if token.Nonce == "" {
		return nil, errors.New("oidc: no nonce present in ID Token")
	}
	if err = n.nonceSource.ClaimNonce(token.Nonce); err != nil {
		return nil, err
	}
	return payload, nil
}
