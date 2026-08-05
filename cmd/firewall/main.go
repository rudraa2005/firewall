package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"firewall/internal/firewall"
)

func main() {
	cfg, err := firewall.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	app, err := firewall.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer app.Close()

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("listening on %s forwarding to %s", cfg.ListenAddr, cfg.UpstreamURL)

	err = server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
