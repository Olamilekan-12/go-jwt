package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func main() {
	h := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	jsonBytes, err := json.Marshal(h)
	if err != nil {
		panic(err)
	}
	fmt.Println("JSON:   ", string(jsonBytes))
	encoded := base64.RawStdEncoding.EncodeToString(jsonBytes)
	fmt.Println("Encoded:", encoded)
}
