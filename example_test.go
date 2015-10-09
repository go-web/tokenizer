package tokenizer_test

import (
	"crypto/aes"
	"crypto/sha1"
	"fmt"
	"log"
	"time"

	"github.com/go-web/tokenizer"
)

func ExampleToken() {
	aesKey := tokenizer.NewKey(aes.BlockSize)
	hmacKey := tokenizer.NewKey(sha1.BlockSize)
	t, err := tokenizer.New(aesKey, hmacKey, nil)
	if err != nil {
		log.Fatal(err)
	}
	token, err := t.Encode([]byte("hello world"))
	if err != nil {
		log.Fatal(err)
	}
	data, created, err := t.Decode(token)
	if err != nil {
		log.Fatal(err)
	}
	elapsed := time.Since(created)
	fmt.Printf("%s from %ds ago", data, int(elapsed.Seconds()))
	// Output: hello world from 0s ago
}
