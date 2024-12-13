package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/1729prashant/microbloggingplatform/internal/auth"
	"github.com/1729prashant/microbloggingplatform/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const HTTP_SERVER_PORT = "8080"

// Add these new types at the top with your other structs
type BlogPost struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type CreateBlogPostRequest struct {
	Body   string    `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

// Convert database.BlogPost to main.BlogPost
func databaseBlogPostToBlogPost(dbBlogPost database.Blogpost) BlogPost {
	return BlogPost{
		ID:        dbBlogPost.ID,
		CreatedAt: dbBlogPost.CreatedAt,
		UpdatedAt: dbBlogPost.UpdatedAt,
		Body:      dbBlogPost.Body,
		UserID:    dbBlogPost.UserID,
	}
}

// New handler for creating BlogPosts
func (cfg *apiConfig) createBlogPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to read request body")
		return
	}

	var req CreateBlogPostRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate BlogPost length
	if len(req.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "BlogPost is too long")
		return
	}

	// Clean the BlogPost text using the existing cleanBlogPost function
	cleanedBody := cleanChirp(req.Body)

	// Create the BlogPost
	dbBlogPost, err := cfg.db.CreateBlogPost(r.Context(), database.CreateBlogPostParams{
		Body:   cleanedBody,
		UserID: req.UserID,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create BlogPost")
		return
	}

	// Convert and respond with the BlogPost
	BlogPost := databaseBlogPostToBlogPost(dbBlogPost)
	respondWithJSON(w, http.StatusCreated, BlogPost)
}

// Handler for fetching all BlogPosts
func (cfg *apiConfig) GetAllBlogPostsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Create the BlogPost
	dbBlogPosts, err := cfg.db.GetAllBlogPosts(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to fetch posts")
		return
	}

	blogPostsResponse := make([]BlogPost, len(dbBlogPosts))
	for i, post := range dbBlogPosts {
		blogPostsResponse[i] = databaseBlogPostToBlogPost(post)
	}

	respondWithJSON(w, http.StatusOK, blogPostsResponse)

}

// In your main.go, add this new handler
func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	chirpID := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
	if chirpID == "" {
		respondWithError(w, http.StatusBadRequest, "Missing chirp ID")
		return
	}

	// Parse the UUID
	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	// Get the chirp from the database
	dbBlogPost, err := cfg.db.GetBlogPost(r.Context(), chirpUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to fetch chirp")
		return
	}

	// Convert and respond with the chirp
	chirp := databaseBlogPostToBlogPost(dbBlogPost)
	respondWithJSON(w, http.StatusOK, chirp)
}

// User struct for JSON responses
type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

// Struct to hold stateful, in-memory data
type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
}

// Request structs
type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Convert database.User to main.User
func databaseUserToUser(dbUser database.User) User {
	return User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}
}

// Handler for user creation
func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to read request body")
		return
	}

	var req CreateUserRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	dbUser, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	user := databaseUserToUser(dbUser)
	respondWithJSON(w, http.StatusCreated, user)
}

// Updated reset handler with user deletion
func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Check if platform is dev
	if cfg.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "This endpoint is only available in development mode")
		return
	}

	// Delete all users
	err := cfg.db.DeleteAllUsers(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to reset users")
		return
	}

	// Reset the hits counter
	cfg.fileserverHits.Store(0)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Reset successful"))
}

// Request and response structs for the validate_chirp endpoint
type ValidateChirpRequest struct {
	Body string `json:"body"`
}

type ValidateChirpResponse struct {
	CleanedBody string `json:"cleaned_body"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Helper function to respond with JSON
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// Helper function to respond with error
func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJSON(w, code, ErrorResponse{Error: msg})
}

// Helper function to clean profane words from text
func cleanChirp(body string) string {
	profaneWords := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}

	words := strings.Split(body, " ")
	for i, word := range words {
		// Convert to lowercase for comparison, but keep original for non-matches
		wordLower := strings.ToLower(word)
		if profaneWords[wordLower] {
			words[i] = "****"
		}
	}
	return strings.Join(words, " ")
}

// Middleware to increment the fileserverHits counter
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// Handler to return the metrics page as HTML
func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	hits := cfg.fileserverHits.Load()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits)
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

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to read request body")
		return
	}

	var req CreateUserRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	/*
		if req.Email == "" {
			respondWithError(w, http.StatusBadRequest, "Email is required")
			return
		}

		encryptedPassword, err := auth.HashPassword(req.HashedPassword)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to encrypt password")
			return
		}
	*/
	dbUser, err := cfg.db.GetEncryptedPassword(r.Context(), req.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// Check password
	if err := auth.CheckPasswordHash(req.Password, dbUser.HashedPassword); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	user := databaseUserToUser(database.User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	})
	respondWithJSON(w, http.StatusOK, user)
}

func main() {

	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize database queries
	dbQueries := database.New(db)

	// Initialize apiConfig to hold stateful data
	apiCfg := &apiConfig{
		db:       dbQueries,
		platform: platform,
	}

	// Create a new ServeMux
	mux := http.NewServeMux()

	// Create and configure the HTTP server
	httpServer := &http.Server{
		Addr:    ":" + HTTP_SERVER_PORT,
		Handler: mux,
	}

	// Add the API endpoints
	mux.HandleFunc("/api/healthz", readinessHandler)
	mux.HandleFunc("/api/chirps", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			apiCfg.GetAllBlogPostsHandler(w, r)
		case http.MethodPost:
			apiCfg.createBlogPostHandler(w, r)
		default:
			respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})
	mux.HandleFunc("/api/chirps/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/chirps/" {
			switch r.Method {
			case http.MethodGet:
				apiCfg.GetAllBlogPostsHandler(w, r)
			case http.MethodPost:
				apiCfg.createBlogPostHandler(w, r)
			default:
				respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}

		// Only proceed if it's a GET request for a specific chirp
		if r.Method != http.MethodGet {
			respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		chirpID := strings.TrimPrefix(r.URL.Path, "/api/chirps/")

		if chirpID == "" {
			respondWithError(w, http.StatusBadRequest, "Missing chirp ID")
			return
		}

		apiCfg.getChirpByIDHandler(w, r)
	})

	mux.HandleFunc("/api/users", apiCfg.createUserHandler)
	mux.HandleFunc("/api/login", apiCfg.loginHandler)
	mux.HandleFunc("/admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("/admin/reset", apiCfg.resetHandler)

	// Keep the file server path at /app/ and wrap it with the middleware
	fileServer := http.FileServer(http.Dir("./"))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fileServer)))

	// Start the server
	err = httpServer.ListenAndServe()
	if err != nil {
		panic(err) // Log error if the server fails to start
	}
}
