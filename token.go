package tokenizer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"time"
)

// Tokenizer errors.
var (
	// ErrInvalidToken indicates the input to Decode
	// is invalid.
	ErrInvalidToken = errors.New("tokenizer: invalid token")

	// ErrInvalidTokenSignature indicates the input to Decode
	// contains an invalid signature.
	ErrInvalidTokenSignature = errors.New("tokenizer: invalid token signature")
)

// NewKey creates a new random key of the given size.
func NewKey(size int) []byte {
	b := make([]byte, size)
	n, err := rand.Read(b)
	if err != nil {
		panic("tokenizer: rand.Read failed: " + err.Error())
	}
	if n != size {
		panic("tokenizer: short read from rand.Read")
	}
	return b
}

// T provides a cryptographic token that can carry user data.
// Tokens consist of user-data encrypted with AES, an HMAC signature
// and a UTC timestamp with second precision.
type T struct {
	aes  cipher.Block
	hmac func() hash.Hash
}

// New creates and initializes a new tokenizer T.
// sha256.New is used for HMAC in case f is nil.
func New(aesKey, hmacKey []byte, f func() hash.Hash) (*T, error) {
	c, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	if f == nil {
		f = sha256.New
	}
	tok := &T{
		aes:  c,
		hmac: func() hash.Hash { return hmac.New(f, hmacKey) },
	}
	return tok, nil
}

// Encode encodes the given byte slice and returns a token.
func (tok *T) Encode(data []byte) (token []byte, err error) {
	if data == nil {
		data = []byte{}
	}
	body := make([]byte, 4+len(data))
	now := uint32(time.Now().UTC().Unix())
	binary.BigEndian.PutUint32(body, now)
	copy(body[4:], data)
	body, err = pkcs7Pad(body, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	iv := NewKey(aes.BlockSize)
	mode := cipher.NewCBCEncrypter(tok.aes, iv)
	mode.CryptBlocks(body, body)
	hash := tok.hmac()
	// size = len(iv + aesblocks + signature)
	token = make([]byte, len(iv)+len(body)+hash.Size())
	copy(token, iv)
	offset := len(iv)
	copy(token[offset:], body)
	offset += len(body)
	hash.Write(token[:offset])
	copy(token[offset:], hash.Sum(nil))
	b := make([]byte, base64.RawURLEncoding.EncodedLen(len(token)))
	base64.RawURLEncoding.Encode(b, token)
	return b, nil
}

// Decode decodes the given token and return its data
// and creation time in UTC.
func (tok *T) Decode(token []byte) (data []byte, creation time.Time, err error) {
	raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(token)))
	n, err := base64.RawURLEncoding.Decode(raw, token)
	if err != nil {
		return nil, time.Time{}, err
	}
	raw = raw[:n]
	hash := tok.hmac()
	if len(raw) < aes.BlockSize*2+hash.Size() {
		return nil, time.Time{}, ErrInvalidToken
	}
	soff := len(raw) - hash.Size() // signature offset
	hash.Write(raw[:soff])
	want := hash.Sum(nil)
	have := raw[soff:]
	if !hmac.Equal(want, have) {
		return nil, time.Time{}, ErrInvalidTokenSignature
	}
	iv := raw[:aes.BlockSize]
	body := raw[aes.BlockSize:soff]
	if len(body)%aes.BlockSize != 0 {
		return nil, time.Time{}, ErrInvalidToken
	}
	mode := cipher.NewCBCDecrypter(tok.aes, iv)
	mode.CryptBlocks(body, body)
	ts := time.Unix(int64(binary.BigEndian.Uint32(body)), 0)
	body, err = pkcs7Unpad(body, aes.BlockSize)
	if err != nil {
		return nil, time.Time{}, err
	}
	return body[4:], ts.UTC(), nil
}
