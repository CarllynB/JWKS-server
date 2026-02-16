package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/*
This project is a tiny JWKS server for class.
What it does in plain terms:
- Generates two RSA key pairs:
  1) an "active" key (not expired)
  2) an "expired" key (already expired)
- Serves a JWKS endpoint that ONLY publishes the active public key.
- Serves an /auth endpoint that returns a JWT:
  - normal POST /auth -> token signed by active key
  - POST /auth?expired=true -> token signed by expired key (and with an expired exp)
*/

// KeyPair holds everything we need for one RSA key pair + metadata.
type KeyPair struct {
	KID    string        // Key ID (goes in JWT header and in JWKS)
	Priv   *rsa.PrivateKey
	Pub    *rsa.PublicKey
	Expiry time.Time // When this key should be considered expired
}

// Server stores our keys and handlers.
// We keep a now() function so tests can control time easily.
type Server struct {
	mu         sync.RWMutex
	activeKey  KeyPair
	expiredKey KeyPair
	now        func() time.Time
}

// NewServer creates a server with one active key and one expired key.
func NewServer() (*Server, error) {
	active, err := generateKeyPair(2048, time.Now().Add(30*time.Minute))
	if err != nil {
		return nil, err
	}
	expired, err := generateKeyPair(2048, time.Now().Add(-30*time.Minute))
	if err != nil {
		return nil, err
	}

	return &Server{
		activeKey:  active,
		expiredKey: expired,
		now:        time.Now,
	}, nil
}

// Routes wires up our endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Standard JWKS location is often /.well-known/jwks.json
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)

	// /auth is a mock authentication endpoint. No real user checking here.
	mux.HandleFunc("/auth", s.handleAuth)

	return mux
}

// handleJWKS returns public keys in JWKS format.
// Requirement: only serve keys that have NOT expired.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		// REST-friendly: correct method only
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build list of keys to publish (only unexpired ones)
	keys := make([]any, 0, 1)
	if s.activeKey.Expiry.After(s.now()) {
		keys = append(keys, rsaPublicToJWK(s.activeKey.KID, s.activeKey.Pub))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": keys,
	})
}

// handleAuth returns a signed JWT.
// - POST /auth            -> uses active key and unexpired exp
// - POST /auth?expired=1  -> uses expired key and expired exp
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// The spec says: "If the expired query parameter is present..."
	useExpired := false
	if strings.Contains(r.URL.RawQuery, "expired") {
		useExpired = true
	}

	s.mu.RLock()
	var kp KeyPair
	if useExpired {
		kp = s.expiredKey
	} else {
		kp = s.activeKey
	}
	s.mu.RUnlock()

	now := s.now()

	// JWT expiration time:
	// For normal tokens, exp should be in the future.
	// For "expired" tokens, exp should be in the past (we use the expired key's expiry).
	exp := kp.Expiry
	if !useExpired && exp.Before(now) {
		// Shouldn't happen in this simple server, but it's safer to fail loudly.
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",       // pretend we authenticated someone
		"iss": "jwks-server",     // issuer
		"iat": now.Unix(),        // issued at
		"exp": exp.Unix(),        // expiration
	}

	// Create token using RS256 (RSA + SHA-256)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// IMPORTANT: include kid so verifiers know which public key to use.
	token.Header["kid"] = kp.KID

	signed, err := token.SignedString(kp.Priv)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": signed,
	})
}

// generateKeyPair creates an RSA private key and returns the pair + metadata.
func generateKeyPair(bits int, expiry time.Time) (KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		KID:    randomKID(),
		Priv:   priv,
		Pub:    &priv.PublicKey,
		Expiry: expiry,
	}, nil
}

// randomKID makes a short URL-safe identifier for the key.
// Real systems may use a hash of the public key instead; this is fine for class.
func randomKID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// rsaPublicToJWK converts an RSA public key into a JWK object.
// JWKS needs "n" (modulus) and "e" (exponent) base64url encoded.
func rsaPublicToJWK(kid string, pub *rsa.PublicKey) map[string]string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   n,
		"e":   e,
	}
}
