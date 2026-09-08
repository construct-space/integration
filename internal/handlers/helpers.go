package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"

	"construct/integration/internal/config"
	"construct/integration/internal/crypto"
)

// Cfg + Sealer are wired by main.go before mux is built.
var (
	Cfg    *config.Config
	Sealer *crypto.Sealer
)

// WriteJSON writes status + body as JSON. No-op on encode error
// — already too late to recover at that point.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// uuid returns a v4-ish UUID — random with version + variant bits set.
// Same pattern used elsewhere in the Construct backend.
func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
