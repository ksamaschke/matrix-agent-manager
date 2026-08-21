package httpapi

import (
	"encoding/json"
	"net/http"
)

// NewHandler returns the deployment-neutral HTTP handler. Authentication and
// mutating APIs are intentionally not part of this foundation slice.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("GET /readyz", health)
	return mux
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
