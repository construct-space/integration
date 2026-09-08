package handlers

import "net/http"

// Health is the liveness probe. Returns 200 unconditionally; deploy
// systems care only that the process is responsive.
func Health(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, 200, map[string]string{"status": "ok", "service": "integration"})
}
