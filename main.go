package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Claims struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat"`
}

var secret = []byte("my-super-secret-key")

var (
	ErrMalformed    = errors.New("token is malformed")
	ErrBadSignature = errors.New("signature is invalid")
	ErrExpired      = errors.New("token has expired")
)

func encodePart(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sign(unsigned string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func createToken(c Claims) string {
	h := Header{Alg: "HS256", Typ: "JWT"}
	unsigned := encodePart(h) + "." + encodePart(c)
	return unsigned + "." + sign(unsigned, secret)
}

func verifyToken(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}

	unsigned := parts[0] + "." + parts[1]
	expected := sign(unsigned, secret)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, ErrBadSignature
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	if time.Now().Unix() > c.Exp {
		return nil, ErrExpired
	}

	return &c, nil
}

func main() {
	now := time.Now()

	good := createToken(Claims{
		Sub: "user-123", Name: "Ada",
		Iat: now.Unix(), Exp: now.Add(15 * time.Minute).Unix(),
	})

	expired := createToken(Claims{
		Sub: "user-456", Name: "Bob",
		Iat: now.Add(-1 * time.Hour).Unix(), Exp: now.Add(-30 * time.Minute).Unix(),
	})

	tampered := good[:len(good)-2] + "xx"

	tests := map[string]string{
		"good":      good,
		"expired":   expired,
		"tampered":  tampered,
		"malformed": "not.a-token",
	}

	for name, tok := range tests {
		c, err := verifyToken(tok)
		if err != nil {
			fmt.Printf("%-10s -> error: %v\n", name, err)
			continue
		}
		fmt.Printf("%-10s -> ok: sub=%s name=%s\n", name, c.Sub, c.Name)
	}
}
