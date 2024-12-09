package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

const HTTP_SERVER_PORT = "8080"

// Struct to hold stateful, in-memory data
type apiConfig struct {
	fileserverHits atomic.Int32
}

// Middleware to increment the fileserverHits counter
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// Handler to return the current request count as plain text (GET only)
func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	hits := cfg.fileserverHits.Load() // Safely read the counter
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hits: %d", hits)
}

// Handler to reset the request count (POST only)
func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg.fileserverHits.Store(0) // Safely reset the counter
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits counter reset to 0"))
}

// Readiness endpoint to check server health (GET only)
func readinessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	// Initialize apiConfig to hold stateful data
	apiCfg := &apiConfig{}

	// Create a new ServeMux
	mux := http.NewServeMux()

	// Create and configure the HTTP server
	httpServer := &http.Server{
		Addr:    ":" + HTTP_SERVER_PORT,
		Handler: mux,
	}

	// Add the readiness endpoint
	mux.HandleFunc("/api/healthz", readinessHandler)

	// Add the metrics endpoint
	mux.HandleFunc("/api/metrics", apiCfg.metricsHandler)

	// Add the reset endpoint
	mux.HandleFunc("/api/reset", apiCfg.resetHandler)

	// Keep the file server path at /app/ and wrap it with the middleware
	fileServer := http.FileServer(http.Dir("./"))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fileServer)))

	// Start the server
	err := httpServer.ListenAndServe()
	if err != nil {
		panic(err) // Log error if the server fails to start
	}
}
