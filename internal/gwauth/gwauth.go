// Package gwauth handles authentication delegated through the gateway.
// The gateway validates the bearer token against accounts and signs
// outgoing requests with X-Internal-Secret + X-Auth-User-ID. We trust
// those headers iff the shared secret matches.
package gwauth

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey int

const (
	keyUserID ctxKey = iota
	keyOrgID
)

// Trusted reports whether the request is signed by a peer service
// holding the shared secret.
func Trusted(r *http.Request, secret string) bool {
	if secret == "" {
		return false
	}
	return r.Header.Get("X-Internal-Secret") == secret
}

// UserIDFrom returns the verified user id (uuid) for the request,
// or "" if the request is unauthenticated.
func UserIDFrom(r *http.Request) string {
	if v, ok := r.Context().Value(keyUserID).(string); ok {
		return v
	}
	return ""
}

// OrgIDFrom returns the verified org id for the request, or "".
func OrgIDFrom(r *http.Request) string {
	if v, ok := r.Context().Value(keyOrgID).(string); ok {
		return v
	}
	return ""
}

// WithIdentity stamps user + org into the request context.
func WithIdentity(r *http.Request, userID, orgID string) *http.Request {
	ctx := context.WithValue(r.Context(), keyUserID, userID)
	ctx = context.WithValue(ctx, keyOrgID, orgID)
	return r.WithContext(ctx)
}

// HeaderUserID pulls X-Auth-User-ID, trimming whitespace.
func HeaderUserID(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Auth-User-ID"))
}

// HeaderOrgID pulls X-Auth-Org-ID (set by the gateway when an org
// context is active for the caller).
func HeaderOrgID(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Auth-Org-ID"))
}
