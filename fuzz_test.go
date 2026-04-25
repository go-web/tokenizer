package tokenizer

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"testing"
)

// fuzzTokenizer is built once per fuzz run with deterministic keys so the
// corpus stays valid across executions.
func fuzzTokenizer(tb testing.TB) *T {
	tb.Helper()
	aesKey := bytes.Repeat([]byte{0xA5}, aes.BlockSize)
	hmacKey := bytes.Repeat([]byte{0x5A}, sha256.BlockSize)
	tok, err := New(aesKey, hmacKey, nil)
	if err != nil {
		tb.Fatal(err)
	}
	return tok
}

// FuzzPKCS7Unpad verifies pkcs7Unpad never panics on arbitrary input.
func FuzzPKCS7Unpad(f *testing.F) {
	f.Add([]byte("hello\x03\x03\x03"))
	f.Add([]byte("hello world\x01"))
	f.Add([]byte("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = pkcs7Unpad(b, aes.BlockSize)
	})
}

// FuzzDecode verifies Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	tok := fuzzTokenizer(f)
	good, err := tok.Encode([]byte("seed"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(""))
	f.Add([]byte("not base64"))
	f.Add([]byte("AAAA"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = tok.Decode(b)
	})
}

// FuzzRoundTrip asserts Decode(Encode(b)) returns the original input.
func FuzzRoundTrip(f *testing.F) {
	tok := fuzzTokenizer(f)
	f.Add([]byte(""))
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte{0x00}, 16))
	f.Add(bytes.Repeat([]byte{0xff}, 1024))
	f.Fuzz(func(t *testing.T, b []byte) {
		token, err := tok.Encode(b)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, _, err := tok.Decode(token)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		// Encode treats nil and empty equivalently.
		if b == nil {
			b = []byte{}
		}
		if !bytes.Equal(got, b) {
			t.Fatalf("round-trip mismatch: want %q, have %q", b, got)
		}
	})
}
