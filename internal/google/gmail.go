package google

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	gmail "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// NewGmail returns a Gmail service bound to the given token. The
// oauth2.Config's TokenSource auto-refreshes — caller should pass
// the refreshed token back to storage if it changes.
func NewGmail(ctx context.Context, c *oauth2.Config, tok *oauth2.Token) (*gmail.Service, oauth2.TokenSource, error) {
	src := c.TokenSource(ctx, tok)
	svc, err := gmail.NewService(ctx, option.WithTokenSource(src))
	if err != nil {
		return nil, nil, err
	}
	return svc, src, nil
}

// ListThreads returns thread headers matching q (Gmail search syntax).
// labelIDs filters by label (e.g. "INBOX"). pageToken paginates.
func ListThreads(svc *gmail.Service, q string, labelIDs []string, pageToken string, maxResults int64) (*gmail.ListThreadsResponse, error) {
	call := svc.Users.Threads.List("me").MaxResults(maxResults)
	if q != "" {
		call = call.Q(q)
	}
	if len(labelIDs) > 0 {
		call = call.LabelIds(labelIDs...)
	}
	if pageToken != "" {
		call = call.PageToken(pageToken)
	}
	return call.Do()
}

// GetThread returns the full thread (all messages) with payload.
func GetThread(svc *gmail.Service, id string) (*gmail.Thread, error) {
	return svc.Users.Threads.Get("me", id).Format("full").Do()
}

// GetMessage returns a single message with full body parts.
func GetMessage(svc *gmail.Service, id string) (*gmail.Message, error) {
	return svc.Users.Messages.Get("me", id).Format("full").Do()
}

// ListLabels returns all labels (system + user-defined).
func ListLabels(svc *gmail.Service) (*gmail.ListLabelsResponse, error) {
	return svc.Users.Labels.List("me").Do()
}

// ModifyLabels adds/removes labels on a message. Common use:
// removing UNREAD to mark as read.
func ModifyLabels(svc *gmail.Service, msgID string, add, remove []string) (*gmail.Message, error) {
	return svc.Users.Messages.Modify("me", msgID, &gmail.ModifyMessageRequest{
		AddLabelIds:    add,
		RemoveLabelIds: remove,
	}).Do()
}

// SendInput captures everything the send endpoint needs.
type SendInput struct {
	From    string
	To      []string
	Cc      []string
	Bcc     []string
	Subject string
	Body    string // plain text; HTML wrap can be added later
	ReplyTo string // optional in-reply-to header
}

// Send composes a minimal RFC 2822 message and calls users.messages.send.
// Returns the persisted message id (Gmail assigns it).
func Send(svc *gmail.Service, in SendInput) (*gmail.Message, error) {
	if len(in.To) == 0 || in.Subject == "" {
		return nil, fmt.Errorf("to and subject required")
	}
	headers := []string{
		"From: " + in.From,
		"To: " + strings.Join(in.To, ", "),
	}
	if len(in.Cc) > 0 {
		headers = append(headers, "Cc: "+strings.Join(in.Cc, ", "))
	}
	if len(in.Bcc) > 0 {
		headers = append(headers, "Bcc: "+strings.Join(in.Bcc, ", "))
	}
	headers = append(headers,
		"Subject: "+in.Subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	)
	if in.ReplyTo != "" {
		headers = append(headers, "In-Reply-To: "+in.ReplyTo, "References: "+in.ReplyTo)
	}
	raw := strings.Join(headers, "\r\n") + "\r\n\r\n" + in.Body
	encoded := base64.URLEncoding.EncodeToString([]byte(raw))
	return svc.Users.Messages.Send("me", &gmail.Message{Raw: encoded}).Do()
}
