package google

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

// UserInfo is the subset of Google's userinfo endpoint we care about.
type UserInfo struct {
	Sub     string `json:"sub"`     // stable Google user id
	Email   string `json:"email"`   // primary email
	Name    string `json:"name"`    // display name
	Picture string `json:"picture"` // avatar url
}

// FetchUserInfo calls https://openidconnect.googleapis.com/v1/userinfo
// with the just-issued access token. Used right after Exchange so we
// can populate the Connection row's email/name/avatar.
func FetchUserInfo(ctx context.Context, c *oauth2.Config, tok *oauth2.Token) (*UserInfo, error) {
	client := c.Client(ctx, tok)
	req, err := http.NewRequestWithContext(ctx, "GET", "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo: %s (%d)", string(body), resp.StatusCode)
	}
	var u UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}
	return &u, nil
}
