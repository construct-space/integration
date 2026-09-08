// gmail.go — HTTP routes that proxy Gmail API for the authenticated
// user's connected Google account. Every handler loads the connection
// via loadGmail (handles token refresh) before calling the Gmail SDK.
//
//	GET    /api/integration/gmail/threads             — list threads
//	GET    /api/integration/gmail/threads/{id}        — single thread w/ messages
//	GET    /api/integration/gmail/messages/{id}       — single message
//	POST   /api/integration/gmail/messages/{id}/modify  — add/remove labels
//	GET    /api/integration/gmail/labels              — list labels
//	POST   /api/integration/gmail/send                — compose + send
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"construct/integration/internal/google"
)

// GmailListThreads — GET /api/integration/gmail/threads
// Query params:
//
//	account_id  — pick which connection (optional)
//	q           — Gmail search query ("is:unread from:foo")
//	label       — repeatable; LabelIds filter (e.g. "INBOX")
//	max         — page size (1..100, default 20)
//	page_token  — Google's next-page cursor
func GmailListThreads(w http.ResponseWriter, r *http.Request) {
	gctx, err := loadGmail(r.Context(), r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	q := r.URL.Query()
	max, _ := strconv.ParseInt(q.Get("max"), 10, 64)
	if max <= 0 || max > 100 {
		max = 20
	}
	res, err := google.ListThreads(gctx.Svc, q.Get("q"), q["label"], q.Get("page_token"), max)
	if err != nil {
		WriteJSON(w, 502, map[string]any{"error": "gmail: " + err.Error()})
		return
	}
	WriteJSON(w, 200, map[string]any{
		"threads":         res.Threads,
		"next_page_token": res.NextPageToken,
		"result_estimate": res.ResultSizeEstimate,
		"account": map[string]any{
			"id":         gctx.Conn.ID,
			"email":      gctx.Conn.Email,
			"name":       gctx.Conn.Name,
			"avatar_url": gctx.Conn.AvatarURL,
		},
	})
}

// GmailGetThread — GET /api/integration/gmail/threads/{id}.
// Returns the thread with full message bodies (parsed by the client).
func GmailGetThread(w http.ResponseWriter, r *http.Request) {
	gctx, err := loadGmail(r.Context(), r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	id := r.PathValue("id")
	if id == "" {
		WriteJSON(w, 400, map[string]any{"error": "thread id required"})
		return
	}
	t, err := google.GetThread(gctx.Svc, id)
	if err != nil {
		WriteJSON(w, 502, map[string]any{"error": "gmail: " + err.Error()})
		return
	}
	WriteJSON(w, 200, t)
}

// GmailGetMessage — GET /api/integration/gmail/messages/{id}.
func GmailGetMessage(w http.ResponseWriter, r *http.Request) {
	gctx, err := loadGmail(r.Context(), r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	id := r.PathValue("id")
	if id == "" {
		WriteJSON(w, 400, map[string]any{"error": "message id required"})
		return
	}
	m, err := google.GetMessage(gctx.Svc, id)
	if err != nil {
		WriteJSON(w, 502, map[string]any{"error": "gmail: " + err.Error()})
		return
	}
	WriteJSON(w, 200, m)
}

// GmailModifyMessage — POST /api/integration/gmail/messages/{id}/modify.
// Body: { add_labels: ["LABEL_x"], remove_labels: ["UNREAD"] }
// Common use: marking read with remove_labels=["UNREAD"].
func GmailModifyMessage(w http.ResponseWriter, r *http.Request) {
	gctx, err := loadGmail(r.Context(), r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	id := r.PathValue("id")
	if id == "" {
		WriteJSON(w, 400, map[string]any{"error": "message id required"})
		return
	}
	var body struct {
		AddLabels    []string `json:"add_labels"`
		RemoveLabels []string `json:"remove_labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteJSON(w, 400, map[string]any{"error": "invalid body"})
		return
	}
	m, err := google.ModifyLabels(gctx.Svc, id, body.AddLabels, body.RemoveLabels)
	if err != nil {
		WriteJSON(w, 502, map[string]any{"error": "gmail: " + err.Error()})
		return
	}
	WriteJSON(w, 200, m)
}

// GmailListLabels — GET /api/integration/gmail/labels.
// Returns system + user labels. Used to populate the sidebar.
func GmailListLabels(w http.ResponseWriter, r *http.Request) {
	gctx, err := loadGmail(r.Context(), r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	res, err := google.ListLabels(gctx.Svc)
	if err != nil {
		WriteJSON(w, 502, map[string]any{"error": "gmail: " + err.Error()})
		return
	}
	WriteJSON(w, 200, res)
}

// GmailSend — POST /api/integration/gmail/send.
// Body: { account_id?, to, cc?, bcc?, subject, body, reply_to? }
// account_id can also be passed as ?account_id= query param.
func GmailSend(w http.ResponseWriter, r *http.Request) {
	gctx, err := loadGmail(r.Context(), r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var body struct {
		To      []string `json:"to"`
		Cc      []string `json:"cc"`
		Bcc     []string `json:"bcc"`
		Subject string   `json:"subject"`
		Body    string   `json:"body"`
		ReplyTo string   `json:"reply_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteJSON(w, 400, map[string]any{"error": "invalid body"})
		return
	}
	if len(body.To) == 0 || body.Subject == "" {
		WriteJSON(w, 400, map[string]any{"error": "to and subject required"})
		return
	}
	from := gctx.Conn.Email
	if gctx.Conn.Name != "" {
		from = gctx.Conn.Name + " <" + gctx.Conn.Email + ">"
	}
	msg, err := google.Send(gctx.Svc, google.SendInput{
		From:    from,
		To:      cleanList(body.To),
		Cc:      cleanList(body.Cc),
		Bcc:     cleanList(body.Bcc),
		Subject: body.Subject,
		Body:    body.Body,
		ReplyTo: body.ReplyTo,
	})
	if err != nil {
		WriteJSON(w, 502, map[string]any{"error": "gmail: " + err.Error()})
		return
	}
	WriteJSON(w, 200, msg)
}

func cleanList(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
