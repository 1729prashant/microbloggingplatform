package main

import (
	"net/http"
)

const HTTP_SERVER_PORT = "8080"

func main() {

	mux := http.NewServeMux()

	httpServer := &http.Server{
		Addr:    ":" + HTTP_SERVER_PORT,
		Handler: mux,
	}

	// Add the readiness endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Update the file server path to /app/ and strip the /app prefix
	fileServer := http.FileServer(http.Dir("./"))
	mux.Handle("/app/", http.StripPrefix("/app", fileServer))

	// Start the server
	err := httpServer.ListenAndServe()
	if err != nil {
		// Log error if the server fails to start
		panic(err)
	}

}
