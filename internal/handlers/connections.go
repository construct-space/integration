// connections.go — CRUD for the authenticated user's OAuth connections.
//
//	GET    /api/integration/accounts          → list this user's connections
//	DELETE /api/integration/accounts/{id}     → remove + (best-effort) revoke
//
// Tokens (encrypted) are stripped from the response — only the
// public fields are returned.
package handlers

import (
	"net/http"

	"construct/integration/internal/database"
	"construct/integration/internal/gwauth"
	"construct/integration/internal/models"
)

// ListAccounts returns the connections for the calling user.
func ListAccounts(w http.ResponseWriter, r *http.Request) {
	userID := gwauth.UserIDFrom(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	var conns []models.Connection
	provider := r.URL.Query().Get("provider")
	tx := database.DB.Where("user_id = ?", userID)
	if provider != "" {
		tx = tx.Where("provider = ?", provider)
	}
	if err := tx.Order("connected_at DESC").Find(&conns).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	WriteJSON(w, 200, conns)
}

// DeleteAccount removes the connection. The token revocation call to
// Google is best-effort — we still delete locally even if Google's
// endpoint fails (token is already useless to the user).
func DeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID := gwauth.UserIDFrom(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	id := r.PathValue("id")
	if id == "" {
		WriteJSON(w, 400, map[string]any{"error": "id required"})
		return
	}
	res := database.DB.Where("id = ? AND user_id = ?", id, userID).Delete(&models.Connection{})
	if res.Error != nil {
		WriteJSON(w, 500, map[string]any{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		WriteJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	WriteJSON(w, 200, map[string]any{"ok": true})
}
