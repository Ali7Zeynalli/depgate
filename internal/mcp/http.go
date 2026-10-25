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
