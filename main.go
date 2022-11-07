// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nukleros/pod-security-webhook/webhook"
)

func main() {
	webHook, err := webhook.NewWebhook()
	if err != nil {
		panic(fmt.Errorf("%w - error creating webhook", err))
	}

	server := &http.Server{
		Addr: fmt.Sprintf(":%v", webHook.Port), // Listen on all the interfaces
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*webHook.Certificate},
			MinVersion:   tls.VersionTLS12,
		},

		// set timeouts to prevent ddos attacks
		ReadHeaderTimeout: 5 * time.Second,
	}

	server.Handler = webHook.Router

	go func() {
		webHook.Log.InfoF("starting web server on port %v", webHook.Port)
		webHook.Log.Error(server.ListenAndServeTLS("", "").Error())
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	webHook.Log.Info("received shutdown signal, shutting down web server")

	if err := server.Shutdown(context.Background()); err != nil {
		webHook.Log.Fatal("failed to shutdown web server gracefully")
		webHook.Log.Fatal(err.Error())
	}
}
