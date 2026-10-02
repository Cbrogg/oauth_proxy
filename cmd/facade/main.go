package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/httpserver"
	"litellm-oauth-facade/internal/identity"
	"litellm-oauth-facade/internal/logging"
	"litellm-oauth-facade/internal/pocketid"
)

func main() {
	configPath := flag.String("config", "/config/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	log := logging.New(cfg.Server.LogLevel)

	pocketClient := pocketid.NewClient(&cfg.PocketID, log)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := pocketClient.Bootstrap(ctx); err != nil {
		cancel()
		log.Error("pocket id bootstrap failed", "error", err)
		os.Exit(1)
	}
	cancel()

	identityClient := identity.NewClient(cfg, pocketClient)
	srv := httpserver.New(cfg, pocketClient, identityClient, log)

	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("listening", slog.String("addr", cfg.Server.Listen))
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown error", "error", err)
	}
}
