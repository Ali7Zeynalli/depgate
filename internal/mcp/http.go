package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

// HTTPHandler serves MCP over HTTP (the Streamable HTTP transport, JSON
// responses only, no server-initiated stream). The caller is responsible for
// authentication. ?project=<path> sets the default project of the requests, so
// one agent configuration per project points at the same server.
func (s *Server) HTTPHandler() http.Handler {
	s.init()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "use POST (no server-sent event stream)", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
			writeRPC(w, response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32600, "batches are not supported"}})
			return
		}
		ctx := r.Context()
		if p := strings.TrimSpace(r.URL.Query().Get("project")); p != "" {
			ctx = withProject(ctx, filepath.Clean(p))
		}
		// who is calling: the name from our session id, else the User-Agent
		var head struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &head)
		c := caller{via: "http", agent: agentFromSession(r.Header.Get("Mcp-Session-Id"))}
		if head.Method == "initialize" {
			if n := clientName(head.Params); n != "" {
				c.agent = n
			}
		}
		if c.agent == "" {
			c.agent = or(agentFromUA(r.UserAgent()), "agent")
		}
		ctx = withCaller(ctx, c)
		if head.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", sessionID(c.agent))
		}
		resp := s.process(ctx, body)
		if resp == nil {
			w.WriteHeader(http.StatusAccepted) // notification
			return
		}
		writeRPC(w, *resp)
	})
}

func writeRPC(w http.ResponseWriter, v response) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
