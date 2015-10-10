package tokenizer

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func newTokenizer() (*T, error) {
	return New(
		NewKey(aes.BlockSize),
		NewKey(sha256.BlockSize),
		nil,
	)
}

func TestTokenizer(t *testing.T) {
	_, err := New(NewKey(8), NewKey(8), nil)
	if err == nil {
		t.Fatal("short key is not supposed to work")
	}
	_, err = newTokenizer()
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncode(t *testing.T) {
	tok, err := newTokenizer()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tok.Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeErrors(t *testing.T) {
	tok, err := newTokenizer()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = tok.Decode([]byte("not base64"))
	if err == nil {
		t.Fatal("unexpected decode with invalid base64")
	}
	bad := base64.RawURLEncoding.EncodeToString([]byte("fail-me"))
	_, _, err = tok.Decode([]byte(bad))
	if err == nil {
		t.Fatal("unexpected decode with invalid payload")
	}
	l := aes.BlockSize*2 + tok.hmac().Size()
	bad = base64.RawURLEncoding.EncodeToString(make([]byte, l))
	_, _, err = tok.Decode([]byte(bad))
	if err != ErrInvalidTokenSignature {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTokenEncoding(t *testing.T) {
	tok, err := newTokenizer()
	if err != nil {
		t.Fatal(err)
	}
	want := NewKey(1e3)
	token, err := tok.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	have, created, err := tok.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != len(have) {
		t.Fatalf("unexpected length: want %d, have %d",
			len(want), len(have))
	}
	if !bytes.Equal(want, have) {
		t.Fatalf("unexpected text: want %q, have %q",
			want[:20], have[:20])
	}
	if age := time.Since(created); age > 2*time.Second {
		t.Fatalf("token is too old: %s", age)
	}
}

func BenchmarkTokenEncode1block(b *testing.B) {
	tok, err := newTokenizer()
	data := make([]byte, aes.BlockSize)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err = tok.Encode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenDecode1block(b *testing.B) {
	tok, _ := newTokenizer()
	data := make([]byte, aes.BlockSize)
	token, err := tok.Encode(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, _, err = tok.Decode(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenEncode10blocks(b *testing.B) {
	tok, err := newTokenizer()
	data := make([]byte, aes.BlockSize*10)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err = tok.Encode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenDecode10blocks(b *testing.B) {
	tok, _ := newTokenizer()
	data := make([]byte, aes.BlockSize*10)
	token, err := tok.Encode(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, _, err = tok.Decode(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenEncode100blocks(b *testing.B) {
	tok, err := newTokenizer()
	data := make([]byte, aes.BlockSize*100)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err = tok.Encode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenDecode100blocks(b *testing.B) {
	tok, _ := newTokenizer()
	data := make([]byte, aes.BlockSize*100)
	token, err := tok.Encode(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, _, err = tok.Decode(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenEncode1000blocks(b *testing.B) {
	tok, err := newTokenizer()
	data := make([]byte, aes.BlockSize*1000)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err = tok.Encode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenDecode1000blocks(b *testing.B) {
	tok, _ := newTokenizer()
	data := make([]byte, aes.BlockSize*1000)
	token, err := tok.Encode(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, _, err = tok.Decode(token); err != nil {
			b.Fatal(err)
		}
	}
}
