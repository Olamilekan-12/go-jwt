package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
}

func createToken(c Claims) string {
	h := Header{
		Alg: "hs256",
		Typ: "JWT",
	}
	unsigned := encodePart(h) + "." + encodePart(c)
	return unsigned + "." + sign(unsigned, secret)
}

func main() {
	now := time.Now()
	c := Claims{
		Sub:  "user-123",
		Name: "Olamilekan",
		Iat:  now.Unix(),
		Exp:  now.Add(15 * time.Minute).Unix(),
	}

	token := createToken(c)
	fmt.Println("Token:", token)
}
