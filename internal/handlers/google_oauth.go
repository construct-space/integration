// google_oauth.go — Google OAuth2 flow.
//
//	POST /api/integration/google/start
//	  → returns { auth_url } the client opens in a browser.
//
//	GET  /api/integration/google/callback
//	  → Google redirects here with ?code= and ?state=. We exchange,
//	    fetch userinfo, persist (or upsert) a Connection row, then
//	    302 the browser to Cfg.PostCallbackDeepLink so the Tauri host
//	    refreshes its UI.
//
// state is an HMAC-signed token carrying user_id + nonce + expiry so
// the callback can map the redirect back to the originating user
// without trusting any request header.
package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"construct/integration/internal/database"
	"construct/integration/internal/google"
	"construct/integration/internal/gwauth"
	"construct/integration/internal/models"

	"gorm.io/gorm/clause"
)

const stateTTL = 10 * time.Minute

// GoogleStart — POST /api/integration/google/start.
// Builds the consent URL for the authenticated user.
func GoogleStart(w http.ResponseWriter, r *http.Request) {
	userID := gwauth.UserIDFrom(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	conf, err := google.NewConfig(Cfg.GoogleClientID, Cfg.GoogleClientSecret, Cfg.GoogleRedirectURI, nil)
	if err != nil {
		WriteJSON(w, 500, map[string]any{"error": "oauth misconfigured: " + err.Error()})
		return
	}
	state, err := signState(userID, gwauth.OrgIDFrom(r))
	if err != nil {
		WriteJSON(w, 500, map[string]any{"error": "sign state: " + err.Error()})
		return
	}
	WriteJSON(w, 200, map[string]any{
		"auth_url": google.AuthURL(conf, state),
	})
}

// GoogleCallback — GET /api/integration/google/callback.
// Public route (Google calls it). state proves the originating user.
func GoogleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		redirectWithStatus(w, r, "error", errCode)
		return
	}
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		redirectWithStatus(w, r, "error", "missing_params")
		return
	}
	userID, orgID, err := verifyState(state)
	if err != nil {
		redirectWithStatus(w, r, "error", "bad_state")
		return
	}

	conf, err := google.NewConfig(Cfg.GoogleClientID, Cfg.GoogleClientSecret, Cfg.GoogleRedirectURI, nil)
	if err != nil {
		redirectWithStatus(w, r, "error", "misconfigured")
		return
	}
	tok, err := google.Exchange(r.Context(), conf, code)
	if err != nil {
		redirectWithStatus(w, r, "error", "exchange_failed")
		return
	}
	info, err := google.FetchUserInfo(r.Context(), conf, tok)
	if err != nil {
		redirectWithStatus(w, r, "error", "userinfo_failed")
		return
	}

	// Seal tokens before persistence. RefreshToken can be empty on
	// re-consent (Google sometimes withholds it) — keep the prior one
	// if so.
	accessEnc, err := Sealer.Seal([]byte(tok.AccessToken))
	if err != nil {
		redirectWithStatus(w, r, "error", "seal_failed")
		return
	}
	var refreshEnc []byte
	if tok.RefreshToken != "" {
		refreshEnc, err = Sealer.Seal([]byte(tok.RefreshToken))
		if err != nil {
			redirectWithStatus(w, r, "error", "seal_failed")
			return
		}
	}

	// Upsert by (user_id, provider, account_id) so reconnecting the
	// same Google account refreshes tokens instead of duplicating rows.
	now := time.Now().UTC()
	conn := models.Connection{
		ID:              uuid(),
		UserID:          userID,
		OrgID:           orgID,
		Provider:        "google",
		AccountID:       info.Sub,
		Email:           info.Email,
		Name:            info.Name,
		AvatarURL:       info.Picture,
		Scopes:          strings.Join(conf.Scopes, " "),
		AccessTokenEnc:  accessEnc,
		RefreshTokenEnc: refreshEnc,
		TokenExpiry:     tok.Expiry,
		Status:          "connected",
		ConnectedAt:     now,
		LastSyncedAt:    now,
	}

	// Preserve the old refresh token if Google didn't issue a new one.
	var existing models.Connection
	if err := database.DB.Where("user_id = ? AND provider = ? AND account_id = ?",
		userID, "google", info.Sub).First(&existing).Error; err == nil {
		conn.ID = existing.ID
		conn.ConnectedAt = existing.ConnectedAt
		if conn.RefreshTokenEnc == nil {
			conn.RefreshTokenEnc = existing.RefreshTokenEnc
		}
	}

	if err := database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		UpdateAll: true,
	}).Create(&conn).Error; err != nil {
		redirectWithStatus(w, r, "error", "db_save_failed")
		return
	}

	redirectWithStatus(w, r, "connected", info.Email)
}

// redirectWithStatus 302s the browser to the post-callback deep link
// with ?status=...&account=... so the Tauri host can show a toast.
func redirectWithStatus(w http.ResponseWriter, r *http.Request, status, detail string) {
	target := Cfg.PostCallbackDeepLink
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	target += sep + "status=" + url.QueryEscape(status) + "&detail=" + url.QueryEscape(detail)
	http.Redirect(w, r, target, http.StatusFound)
}

// signState packs user_id|org_id|expiry|nonce and HMACs it with the
// service's internal secret. Keeps the callback verifiable without
// stashing pending-flow rows in the DB.
func signState(userID, orgID string) (string, error) {
	if Cfg.InternalSecret == "" {
		return "", fmt.Errorf("internal secret unset; cannot sign state")
	}
	expiry := time.Now().Add(stateTTL).Unix()
	nonce := uuid()
	payload := fmt.Sprintf("%s|%s|%d|%s", userID, orgID, expiry, nonce)
	mac := hmac.New(sha256.New, []byte(Cfg.InternalSecret))
	_, _ = mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	raw := payload + "|" + sig
	return base64.RawURLEncoding.EncodeToString([]byte(raw)), nil
}

func verifyState(state string) (userID, orgID string, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return "", "", fmt.Errorf("decode state")
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 5 {
		return "", "", fmt.Errorf("malformed state")
	}
	uid, oid, expStr, nonce, sig := parts[0], parts[1], parts[2], parts[3], parts[4]
	payload := fmt.Sprintf("%s|%s|%s|%s", uid, oid, expStr, nonce)
	mac := hmac.New(sha256.New, []byte(Cfg.InternalSecret))
	_, _ = mac.Write([]byte(payload))
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return "", "", fmt.Errorf("bad signature")
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", "", fmt.Errorf("bad expiry")
	}
	if time.Now().Unix() > expUnix {
		return "", "", fmt.Errorf("state expired")
	}
	return uid, oid, nil
}
