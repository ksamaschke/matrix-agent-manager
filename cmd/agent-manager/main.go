package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/ksamaschke/matrix-agent-manager/internal/config"
	"github.com/ksamaschke/matrix-agent-manager/internal/httpapi"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(2)
	}

	server := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: httpapi.NewHandler(),
	}
	slog.Info("starting matrix agent manager", "environment", cfg.Environment, "addr", cfg.HTTPAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
