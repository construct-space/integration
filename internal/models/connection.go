// Package models holds the persisted shapes for the integration
// service. Currently one table: oauth_connections.
package models

import "time"

// Connection is one user's link to an external provider account
// (Gmail, Google Calendar, Slack, …). Tokens are stored sealed —
// AccessTokenEnc / RefreshTokenEnc are AES-GCM ciphertext, never
// the raw values. Access tokens are refreshed on demand from the
// long-lived refresh token.
type Connection struct {
	ID        string `json:"id" gorm:"primarykey;size:36"`
	UserID    string `json:"user_id" gorm:"size:36;index;not null"`
	OrgID     string `json:"org_id" gorm:"size:36;index"`
	Provider  string `json:"provider" gorm:"size:32;index;not null"`
	AccountID string `json:"account_id" gorm:"size:255;index"` // provider's stable id (sub / google_id)
	Email     string `json:"email" gorm:"size:255;index"`
	Name      string `json:"name" gorm:"size:255"`
	AvatarURL string `json:"avatar_url" gorm:"type:text"`
	Scopes    string `json:"scopes" gorm:"type:text"` // space-separated

	AccessTokenEnc  []byte    `json:"-" gorm:"type:blob"`
	RefreshTokenEnc []byte    `json:"-" gorm:"type:blob"`
	TokenExpiry     time.Time `json:"-"`

	Status       string    `json:"status" gorm:"size:32;default:connected"`
	LastSyncedAt time.Time `json:"last_synced_at"`
	ConnectedAt  time.Time `json:"connected_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (Connection) TableName() string { return "oauth_connections" }
