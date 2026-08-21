package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ksamaschke/matrix-agent-manager/internal/agents"
	"github.com/ksamaschke/matrix-agent-manager/internal/config"
	"github.com/ksamaschke/matrix-agent-manager/internal/httpapi"
	"github.com/ksamaschke/matrix-agent-manager/internal/mas"
	"github.com/ksamaschke/matrix-agent-manager/internal/oidcauth"
	"github.com/ksamaschke/matrix-agent-manager/internal/session"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	if cfg.Environment != "production" {
		slog.Error("agent manager refuses to start outside production wiring; use the test binary or explicit integration configuration", "environment", cfg.Environment)
		os.Exit(2)
	}

	sessionKey, err := os.ReadFile(cfg.SessionKeyFile)
	if err != nil {
		fatal("read session key", err)
	}
	codec, err := session.NewKey(strings.TrimSpace(string(sessionKey)), time.Now)
	if err != nil {
		fatal("create session codec", err)
	}
	stateStore := oidcauth.NewMemoryStateStore()
	// Production is single-replica until a shared StateStore implementation is
	// configured. This prevents silently unsafe multi-replica OIDC behavior.
	auth, err := oidcauth.New(context.Background(), oidcauth.Config{
		IssuerURL:        cfg.OIDCIssuerURL,
		ClientID:         cfg.OIDCClientID,
		ClientSecretFile: cfg.OIDCClientSecretFile,
		Audience:         cfg.OIDCAudience,
		RedirectURL:      cfg.OIDCRedirectURL,
		RolesClaim:       cfg.OIDCRolesClaim,
		RequiredRoles:    cfg.OIDCRequiredRoles,
		CookieSecure:     cfg.CookieSecure,
		Codec:            codec,
		StateStore:       stateStore,
	})
	if err != nil {
		fatal("initialize OIDC", err)
	}

	masClient, err := mas.NewClient(mas.ClientConfig{
		TokenURL:            cfg.MASTokenURL,
		UsersURL:            cfg.MASUsersURL,
		PersonalSessionsURL: cfg.MASPersonalSessionsURL,
		ClientID:            cfg.MASClientID,
		ClientSecretFile:    cfg.MASClientSecretFile,
	}, nil)
	if err != nil {
		fatal("initialize MAS client", err)
	}
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		fatal("load in-cluster Kubernetes configuration", err)
	}
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		fatal("initialize Kubernetes client", err)
	}
	backend, err := agents.NewKubernetesBackend(kubeClient, cfg.SecretNamespace, "matrix-agent")
	if err != nil {
		fatal("initialize Kubernetes Secret backend", err)
	}
	service := agents.NewService(masClient, backend, agents.ServiceConfig{
		SecretNamePrefix: "matrix-agent",
		TokenScope:       "openid urn:matrix:client:api:*",
		TokenExpiry:      30 * 24 * time.Hour,
	})
	httpServer, err := httpapi.NewServer(auth, service, httpapi.ServerConfig{
		AdminRoles:  []string{"matrix-agent-admin"},
		ViewerRoles: []string{"matrix-agent-admin", "matrix-agent-viewer"},
	})
	if err != nil {
		fatal("initialize HTTP API", err)
	}
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: httpServer.NewHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	slog.Info("starting matrix agent manager", "environment", cfg.Environment, "addr", cfg.HTTPAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal("server stopped", err)
	}
}

func fatal(message string, err error) {
	slog.Error(message, "error", err)
	os.Exit(1)
}
