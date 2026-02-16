package main

import (
	"log"
	"net/http"
)

/*
Entry point.
Starts the server on port 8080.
*/
func main() {
	s, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("JWKS server listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", s.Routes()))
}
