// +build gofuzz

// go-fuzz-build github.com/go-web/tokenizer
// go-fuzz -bin=./tokenizer-fuzz.zip -workdir=fuzzdata

package tokenizer

import (
	"crypto/aes"
	"crypto/sha256"
)

var tok, _ = New(NewKey(aes.BlockSize), NewKey(sha256.BlockSize), nil)
var iv = NewKey(aes.BlockSize)

func Fuzz(data []byte) int {
	b, err := pkcs7Pad(data, 16)
	if err != nil {
		if b != nil {
			panic("b != nil on error")
		}
		return 0
	}
	b, err = pkcs7Unpad(data, 16)
	if err != nil {
		if b != nil {
			panic("b != nil on error")
		}
		return 0
	}
	b, err = tok.Encode(data)
	if err != nil {
		if b != nil {
			panic("b != nil on error")
		}
	}
	b, _, err = tok.Decode(data)
	if err != nil {
		if b != nil {
			panic("b != nil on error")
		}
	}
	return 1
}
