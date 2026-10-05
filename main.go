package main

import (
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

func encodePart(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func main() {
	h := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	now := time.Now()
	c := Claims{
		Sub:  "user-123",
		Name: "Olamilekan",
		Iat:  now.Unix(),
		Exp:  now.Add(15 * time.Minute).Unix(),
	}

	header := encodePart(h)
	payload := encodePart(c)

	fmt.Println("Header: ", header)
	fmt.Println("Payload: ", payload)
	fmt.Println("Unsigned", header+"."+payload)
}
