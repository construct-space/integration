// Package config loads runtime configuration for the integration
// service. Env vars only — no flag parsing — so the same binary works
// in dev, docker, and managed deploys without recompilation.
package config

import (
	"bufio"
	"os"
	"strings"
)

// Config groups everything the integration service needs at startup.
// Sensitive fields (DB pass, OAuth client secret, encryption key)
// have no defaults so a misconfigured deploy refuses to start.
type Config struct {
	Port           string
	AppURL         string
	AllowedOrigins []string

	DBDriver string
	DBHost   string
	DBPort   string
	DBName   string
	DBUser   string
	DBPass   string

	// AccountsURL is the accounts service base URL used to validate
	// bearer tokens that come through the gateway. Matches the same
	// env var the source service reads.
	AccountsURL string

	// InternalSecret gates /internal/* routes — service-to-service
	// callers (other Construct backends) must present this. Same
	// value as INTERNAL_SHARED_SECRET on peer services.
	InternalSecret string

	// EncryptionKey — 32-byte (256-bit) AES key, hex-encoded.
	// Refresh tokens are AES-GCM sealed under this before storage.
	EncryptionKey string

	// Google OAuth client. ClientID is bundle-safe; ClientSecret
	// stays here only.
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string

	// PostCallbackDeepLink is the construct:// URL the callback
	// handler 302s the browser to after a successful exchange, so
	// the Tauri host can refresh the connected-accounts UI.
	// Defaults to construct://app/mail/settings.
	PostCallbackDeepLink string
}

func Load() *Config {
	loadEnvFile(".env")

	origins := splitCSV(env("ALLOWED_ORIGINS", "https://my.lisaos.dev,tauri://localhost,http://localhost:3000"))

	return &Config{
		Port:           env("PORT", "8020"),
		AppURL:         env("APP_URL", "http://localhost:8020"),
		AllowedOrigins: origins,

		DBDriver: env("DB_DRIVER", "mysql"),
		DBHost:   env("DB_HOST", "localhost"),
		DBPort:   env("DB_PORT", "3306"),
		DBName:   env("DB_NAME", "construct_integration"),
		DBUser:   env("DB_USER", "root"),
		DBPass:   env("DB_PASS", ""),

		AccountsURL: env("ACCOUNTS_URL", "https://accounts.lisaos.dev"),

		InternalSecret: env("INTERNAL_SHARED_SECRET", env("SERVICE_API_KEY", "")),
		EncryptionKey:  env("INTEGRATION_ENCRYPTION_KEY", ""),

		GoogleClientID:     env("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: env("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURI:  env("GOOGLE_REDIRECT_URI", ""),

		PostCallbackDeepLink: env("POST_CALLBACK_DEEP_LINK", "construct://app/mail/settings"),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
