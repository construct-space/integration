// Package google wraps the Google OAuth2 client + Gmail API helpers
// the rest of the service uses. Keeps the oauth2.Config construction
// in one place so handlers don't repeat scope/endpoint plumbing.
package google

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	googleOauth "golang.org/x/oauth2/google"
)

// DefaultScopes is the minimum we ask for to deliver a Gmail client.
//   - openid / email / profile  → identify the connecting user
//   - gmail.modify              → read messages, mark read, label changes
//   - gmail.send                → outgoing mail
//
// We deliberately avoid gmail.readonly (subset of modify) and
// gmail.compose (subset of send). Fewer scopes = simpler verification.
var DefaultScopes = []string{
	"openid",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
	"https://www.googleapis.com/auth/gmail.modify",
	"https://www.googleapis.com/auth/gmail.send",
}

// NewConfig builds the oauth2.Config used for both the auth-URL
// generation and the code-for-token exchange.
func NewConfig(clientID, clientSecret, redirectURI string, scopes []string) (*oauth2.Config, error) {
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("google client id/secret missing")
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("google redirect uri missing")
	}
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       scopes,
		Endpoint:     googleOauth.Endpoint,
	}, nil
}

// AuthURL returns the Google consent URL with offline + force-consent
// so we always get a refresh token (Google only returns a refresh
// token on first consent unless you force it).
func AuthURL(c *oauth2.Config, state string) string {
	return c.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
	)
}

// Exchange swaps an auth code for an access + refresh token pair.
func Exchange(ctx context.Context, c *oauth2.Config, code string) (*oauth2.Token, error) {
	return c.Exchange(ctx, code)
}
