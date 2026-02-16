package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/*
Tests focus on the rubric items:
- JWKS contains a valid unexpired JWK and does NOT include expired keys
- /auth returns a valid JWT with correct kid header
- /auth?expired returns a token signed by the expired key and is expired
- correct HTTP methods return 405
*/

func TestJWKSOnlyServesUnexpired(t *testing.T) {
	s, _ := NewServer()
	s.now = func() time.Time { return time.Now() }

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}

	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)

	if len(body.Keys) != 1 {
		t.Fatalf("expected 1 key got %d", len(body.Keys))
	}
	if body.Keys[0]["kid"] != s.activeKey.KID {
		t.Fatalf("expected active kid in JWKS")
	}
}

func TestAuthReturnsValidJWTWithKid(t *testing.T) {
	s, _ := NewServer()
	now := time.Now()
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	parsed, err := jwt.Parse(resp.Token, func(token *jwt.Token) (any, error) {
		if token.Header["kid"] != s.activeKey.KID {
			t.Fatalf("expected kid header to match active key")
		}
		return s.activeKey.Pub, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("token invalid: %v", err)
	}
}

func TestExpiredAuthUsesExpiredKeyAndExpiredExp(t *testing.T) {
	s, _ := NewServer()
	now := time.Now()
	s.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	// We expect Parse() to report expired (so token should not be valid).
	parsed, err := jwt.Parse(resp.Token, func(token *jwt.Token) (any, error) {
		if token.Header["kid"] != s.expiredKey.KID {
			t.Fatalf("expected kid header to match expired key")
		}
		return s.expiredKey.Pub, nil
	})

	// If it's valid, that's wrong because exp is in the past.
	if err == nil && parsed != nil && parsed.Valid {
		t.Fatalf("expected token to be expired and invalid")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s, _ := NewServer()

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", strings.NewReader(""))
	rr2 := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 got %d", rr2.Code)
	}
}
