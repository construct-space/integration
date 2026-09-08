// gmail_helpers.go — shared lookup + token-refresh logic for every
// Gmail handler. Loads the user's Connection, decrypts the stored
// tokens, builds a Gmail service whose TokenSource auto-refreshes,
// and persists any rotated access token before returning.
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"construct/integration/internal/database"
	"construct/integration/internal/google"
	"construct/integration/internal/gwauth"
	"construct/integration/internal/models"

	"golang.org/x/oauth2"
	gmail "google.golang.org/api/gmail/v1"
)

// gmailContext bundles everything a handler needs to talk to Gmail
// for one request: the Gmail service, the connection record (so we
// know the user's email, account_id, etc.), and the original oauth2
// token (which the caller can re-fetch from the TokenSource if it
// wants the refreshed value).
type gmailContext struct {
	Svc  *gmail.Service
	Conn *models.Connection
}

// loadGmail returns a ready Gmail service for the authenticated
// user. If multiple connections exist, ?account_id= picks one
// (either by oauth_connections.id or by Google sub). Without a
// hint, the most-recently-connected account is used.
//
// On success, any refreshed access token has already been
// re-encrypted and saved back. The caller doesn't need to think
// about token lifetimes.
func loadGmail(ctx context.Context, r *http.Request) (*gmailContext, error) {
	userID := gwauth.UserIDFrom(r)
	if userID == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	accountHint := r.URL.Query().Get("account_id")

	tx := database.DB.Where("user_id = ? AND provider = ?", userID, "google")
	if accountHint != "" {
		// Match either the row id or the Google sub — easier on callers
		// who only remember one of the two.
		tx = tx.Where("id = ? OR account_id = ?", accountHint, accountHint)
	}
	var conn models.Connection
	if err := tx.Order("connected_at DESC").First(&conn).Error; err != nil {
		return nil, fmt.Errorf("no connected google account: %w", err)
	}
	if len(conn.RefreshTokenEnc) == 0 {
		return nil, fmt.Errorf("connection has no refresh token; reconnect")
	}

	refresh, err := Sealer.Open(conn.RefreshTokenEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt refresh token: %w", err)
	}
	var access []byte
	if len(conn.AccessTokenEnc) > 0 {
		if access, err = Sealer.Open(conn.AccessTokenEnc); err != nil {
			// Access token corrupted/old format — drop it and let
			// the refresh token mint a new one.
			access = nil
		}
	}

	cfg, err := google.NewConfig(Cfg.GoogleClientID, Cfg.GoogleClientSecret, Cfg.GoogleRedirectURI, nil)
	if err != nil {
		return nil, err
	}

	tok := &oauth2.Token{
		AccessToken:  string(access),
		RefreshToken: string(refresh),
		Expiry:       conn.TokenExpiry,
		TokenType:    "Bearer",
	}
	svc, src, err := google.NewGmail(ctx, cfg, tok)
	if err != nil {
		return nil, err
	}

	// Fetch potentially-refreshed token so we can persist if it
	// rotated. golang.org/x/oauth2 only rotates lazily on demand;
	// touching Token() forces it.
	if refreshed, err := src.Token(); err == nil && refreshed != nil {
		if refreshed.AccessToken != tok.AccessToken {
			if newAcc, sErr := Sealer.Seal([]byte(refreshed.AccessToken)); sErr == nil {
				conn.AccessTokenEnc = newAcc
				conn.TokenExpiry = refreshed.Expiry
				conn.LastSyncedAt = time.Now().UTC()
				conn.Status = "connected"
				database.DB.Save(&conn)
			}
		}
	}

	return &gmailContext{Svc: svc, Conn: &conn}, nil
}
