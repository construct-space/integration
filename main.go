// integration-api — third-party OAuth + provider proxies.
//
// First provider: Google (Gmail). Adding Calendar / Slack / Drive
// reuses the same crypto / connection table / handler shape.
//
// Routing groups:
//   /api/integration/*      — gateway-auth required (user-facing)
//   /internal/integration/* — peer-service callers only (X-Internal-Secret)
//   /health                 — public liveness
package main

import (
	"log"
	"net/http"
	"time"

	"construct/integration/internal/config"
	"construct/integration/internal/crypto"
	"construct/integration/internal/database"
	"construct/integration/internal/handlers"
	"construct/integration/internal/middleware"
)

func main() {
	cfg := config.Load()
	handlers.Cfg = cfg

	sealer, err := crypto.New(cfg.EncryptionKey)
	if err != nil {
		log.Fatalf("init crypto: %v", err)
	}
	handlers.Sealer = sealer

	database.Init(cfg)

	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /health", handlers.Health)
	mux.HandleFunc("GET /api/health", handlers.Health)

	// Public — Google's OAuth redirect target. Validated via signed state.
	mux.HandleFunc("GET /api/integration/google/callback", handlers.GoogleCallback)

	// Gateway-authenticated (X-Internal-Secret + X-Auth-User-ID).
	gw := middleware.GatewayAuth(cfg)
	mux.Handle("POST /api/integration/google/start", gw(http.HandlerFunc(handlers.GoogleStart)))
	mux.Handle("GET /api/integration/accounts", gw(http.HandlerFunc(handlers.ListAccounts)))
	mux.Handle("DELETE /api/integration/accounts/{id}", gw(http.HandlerFunc(handlers.DeleteAccount)))

	// Gmail proxy. Each handler loads the user's connection, refreshes
	// the token if needed, then forwards to the Gmail API.
	mux.Handle("GET /api/integration/gmail/threads", gw(http.HandlerFunc(handlers.GmailListThreads)))
	mux.Handle("GET /api/integration/gmail/threads/{id}", gw(http.HandlerFunc(handlers.GmailGetThread)))
	mux.Handle("GET /api/integration/gmail/messages/{id}", gw(http.HandlerFunc(handlers.GmailGetMessage)))
	mux.Handle("POST /api/integration/gmail/messages/{id}/modify", gw(http.HandlerFunc(handlers.GmailModifyMessage)))
	mux.Handle("GET /api/integration/gmail/labels", gw(http.HandlerFunc(handlers.GmailListLabels)))
	mux.Handle("POST /api/integration/gmail/send", gw(http.HandlerFunc(handlers.GmailSend)))

	handler := middleware.TrimTrailingSlash(middleware.Logger(middleware.CORS(cfg)(mux)))

	log.Printf("integration-api listening on :%s", cfg.Port)
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
