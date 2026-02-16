# JWKS Server (Project 1)

A small JWKS server for class.

## What it does
- Runs on **port 8080**
- `GET /.well-known/jwks.json` returns **only unexpired public keys**
- `POST /auth` returns a **valid RS256 JWT** signed by the active key
- `POST /auth?expired=true` returns a JWT signed by the **expired key** and with an **expired exp**

JWTs include `kid` in the header so a client can select the right key from JWKS.

## Run it
1. Install Go (1.22+)
2. In this folder, run:

```bash
go mod tidy
go run .
```

Server starts at: `http://localhost:8080`

## Try it quickly
```bash
curl -s http://localhost:8080/.well-known/jwks.json
curl -s -X POST http://localhost:8080/auth
curl -s -X POST "http://localhost:8080/auth?expired=true"
```

## Tests + coverage
```bash
go test ./... -cover
```

