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

	// Get and validate JWT
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
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

	// Clean the BlogPost
	cleanedBody := cleanChirp(req.Body)

	// Create the BlogPost
	dbBlogPost, err := cfg.db.CreateBlogPost(r.Context(), database.CreateBlogPostParams{
		Body:   cleanedBody,
		UserID: userID, // Use the ID from the JWT
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
	/*
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
	*/

	// Extract query parameters
	authorIDStr := r.URL.Query().Get("author_id")
	sortOrder := r.URL.Query().Get("sort")

	// Default to "asc" if no sort parameter is provided
	if sortOrder == "" {
		sortOrder = "asc"
	}

	// Validate sortOrder to ensure it's either 'asc' or 'desc'
	if sortOrder != "asc" && sortOrder != "desc" {
		respondWithError(w, http.StatusBadRequest, "Invalid sort value")
		return
	}

	// Convert author_id to UUID if present
	var authorID uuid.UUID
	if authorIDStr != "" {
		parsedID, err := uuid.Parse(authorIDStr)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid author_id format")
			return
		}
		authorID = parsedID
	}

	// Fetch blogposts from the database, passing authorID and sortOrder
	if sortOrder == "desc" && authorIDStr != "" {
		dbBlogPosts, err := cfg.db.GetBlogPostsDesc(r.Context(), authorID)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to fetch chirps")
			return
		}
		blogPostsResponse := make([]BlogPost, len(dbBlogPosts))
		for i, post := range dbBlogPosts {
			blogPostsResponse[i] = databaseBlogPostToBlogPost(post)
		}
		respondWithJSON(w, http.StatusOK, blogPostsResponse)

	}
	if (sortOrder == "asc" || sortOrder == "") && authorIDStr != "" {
		dbBlogPosts, err := cfg.db.GetBlogPostsAsc(r.Context(), authorID)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to fetch chirps")
			return
		}
		blogPostsResponse := make([]BlogPost, len(dbBlogPosts))
		for i, post := range dbBlogPosts {
			blogPostsResponse[i] = databaseBlogPostToBlogPost(post)
		}
		respondWithJSON(w, http.StatusOK, blogPostsResponse)
	}

	if sortOrder == "desc" && authorIDStr == "" {
		dbBlogPosts, err := cfg.db.GetAllBlogPostsDesc(r.Context())
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to fetch chirps")
			return
		}
		blogPostsResponse := make([]BlogPost, len(dbBlogPosts))
		for i, post := range dbBlogPosts {
			blogPostsResponse[i] = databaseBlogPostToBlogPost(post)
		}
		respondWithJSON(w, http.StatusOK, blogPostsResponse)

	}
	if (sortOrder == "asc" || sortOrder == "") && authorIDStr == "" {
		dbBlogPosts, err := cfg.db.GetAllBlogPosts(r.Context())
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to fetch chirps")
			return
		}
		blogPostsResponse := make([]BlogPost, len(dbBlogPosts))
		for i, post := range dbBlogPosts {
			blogPostsResponse[i] = databaseBlogPostToBlogPost(post)
		}
		respondWithJSON(w, http.StatusOK, blogPostsResponse)
	}

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
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

// Struct to hold stateful, in-memory data
type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

// Request structs
type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Convert database.User to main.User
func databaseUserToUser(dbUser database.User) User {
	// Check if the sql.NullBool is valid and return its value, else default to false
	isChirpyRed := false
	if dbUser.IsChirpyRed.Valid {
		isChirpyRed = dbUser.IsChirpyRed.Bool
	}

	return User{
		ID:          dbUser.ID,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		Email:       dbUser.Email,
		IsChirpyRed: isChirpyRed,
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

// Add new login request struct
type LoginRequest struct {
	Password         string `json:"password"`
	Email            string `json:"email"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
}

// Add response struct with token
type LoginResponse struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
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

	var req LoginRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}

	// Get user from database
	dbUser, err := cfg.db.GetEncryptedPassword(r.Context(), req.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	// Check password
	if err := auth.CheckPasswordHash(req.Password, dbUser.HashedPassword); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	// Create JWT (expires in 1 hour)
	token, err := auth.MakeJWT(dbUser.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create token")
		return
	}

	// Create Refresh Token (expires in 60 days)
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create refresh token")
		return
	}

	// Insert Refresh Token into database
	expiresAt := sql.NullTime{Time: time.Now().AddDate(0, 2, 0), Valid: true} // 60 days
	revokedAt := sql.NullTime{}                                               // Null
	_, err = cfg.db.InsertRefreshToken(r.Context(), database.InsertRefreshTokenParams{
		Token:     refreshToken,
		UserID:    dbUser.ID,
		ExpiresAt: expiresAt,
		RevokedAt: revokedAt,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to store refresh token")
		return
	}

	// Respond with tokens
	response := LoginResponse{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  dbUser.IsChirpyRed.Bool,
	}

	respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	// Look up the refresh token in the database
	dbToken, err := cfg.db.GetRefreshToken(r.Context(), token)
	if err != nil || !dbToken.ExpiresAt.Valid || dbToken.ExpiresAt.Time.Before(time.Now()) || dbToken.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	// Create a new JWT (expires in 1 hour)
	newToken, err := auth.MakeJWT(dbToken.UserID, cfg.jwtSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create token")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"token": newToken})
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	// Revoke the token
	err = cfg.db.RevokeRefreshToken(r.Context(), database.RevokeRefreshTokenParams{
		Token:     token,
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
		UpdatedAt: time.Now(),
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to revoke token")
		return
	}

	w.WriteHeader(http.StatusNoContent) // 204 No Content
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is PUT
	if r.Method != http.MethodPut {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Validate the access token
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	// Get the user ID from the access token
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	// Read and parse the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to read request body")
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err = json.Unmarshal(body, &req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate the inputs
	if req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}
	if req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required")
		return
	}

	// Hash the new password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	// Update the user's email and password in the database
	err = cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}

	// Fetch the updated user
	dbUser, err := cfg.db.GetUser(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to fetch updated user")
		return
	}

	// Convert and respond with the updated user (excluding password)
	user := User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}
	respondWithJSON(w, http.StatusOK, user)
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract the chirpID from the URL
	chirpID := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
	if chirpID == "" {
		respondWithError(w, http.StatusBadRequest, "Missing chirp ID")
		return
	}

	// Parse chirpID as UUID
	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	// Validate the access token
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	// Get the user ID from the access token
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	// Check if the chirp exists and belongs to the user
	chirp, err := cfg.db.GetBlogPost(r.Context(), chirpUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to fetch chirp")
		return
	}

	// Check if the authenticated user is the owner
	if chirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "You are not the author of this chirp")
		return
	}

	// Delete the chirp
	err = cfg.db.DeleteBlogPost(r.Context(), database.DeleteBlogPostParams{
		ID:     chirpUUID,
		UserID: chirp.UserID,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to delete chirp")
		return
	}

	// Respond with 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract API key from the Authorization header
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}

	// Check if the API key matches the one stored in the config
	if apiKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Parse the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var req struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	// Ignore events other than "user.upgraded"
	if req.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Parse the user ID
	userID, err := uuid.Parse(req.Data.UserID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	// Upgrade the user to Chirpy Red
	err = cfg.db.UpgradeToChirpyRed(r.Context(), userID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to upgrade user")
		return
	}

	// Respond with 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

func main() {

	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize database queries
	dbQueries := database.New(db)

	// Initialize apiConfig to hold stateful data
	apiCfg := &apiConfig{
		db:        dbQueries,
		platform:  platform,
		jwtSecret: jwtSecret,
		polkaKey:  polkaKey,
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

		// Handle specific chirp by ID (`/api/chirps/{chirpID}`)
		chirpID := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
		if chirpID == "" {
			respondWithError(w, http.StatusBadRequest, "Missing chirp ID")
			return
		}

		switch r.Method {
		case http.MethodGet:
			apiCfg.getChirpByIDHandler(w, r)
		case http.MethodDelete:
			apiCfg.deleteChirpHandler(w, r)
		default:
			respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			apiCfg.createUserHandler(w, r) // Existing handler for POST
		case http.MethodPut:
			apiCfg.updateUserHandler(w, r) // New handler for PUT
		default:
			respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})
	mux.HandleFunc("/api/login", apiCfg.loginHandler)
	mux.HandleFunc("/api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("/api/revoke", apiCfg.revokeHandler)
	mux.HandleFunc("/api/polka/webhooks", apiCfg.polkaWebhookHandler)
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
