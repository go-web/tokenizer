package tokenizer

import (
	"bytes"
	"testing"
)

func TestPKCS7Pad(t *testing.T) {
	test := []struct {
		Input,
		Want []byte
		BlockSize int
		Err       error
	}{
		{[]byte("a"), nil, 0, ErrInvalidBlockSize},
		{[]byte{}, nil, 1, ErrInvalidPKCS7Data},
		{[]byte("hello"), []byte("hello\x03\x03\x03"), 4, nil},
		{[]byte("hello world"), []byte("hello world\x01"), 4, nil},
		{[]byte("helloworld"), []byte("helloworld\x02\x02"), 3, nil},
		{[]byte("helloworld"), []byte("helloworld\x02\x02"), 4, nil},
		{[]byte("hello"), []byte("hello\x05\x05\x05\x05\x05"), 5, nil},
	}
	e1 := "unexpected error for item %d, %q: "
	e2 := "failed padding item %d, %q: "
	for n, el := range test {
		have, err := pkcs7Pad(el.Input, el.BlockSize)
		if err != el.Err {
			t.Fatalf(e1+"want \"%v\", have \"%v\"",
				n, el.Input, el.Err, err)
		}
		if !bytes.Equal(have, el.Want) {
			t.Fatalf(e2+"want %q, have %q",
				n, el.Input, el.Want, have)
		}
	}
}

func TestPKCS7Unpad(t *testing.T) {
	test := []struct {
		Input,
		Want []byte
		BlockSize int
		Err       error
	}{
		{[]byte("a"), nil, 0, ErrInvalidBlockSize},
		{[]byte{}, nil, 1, ErrInvalidPKCS7Data},
		{[]byte("hello"), nil, 4, ErrInvalidPKCS7Padding},
		{[]byte("hello\x03\x03\x03"), []byte("hello"), 4, nil},
		{[]byte("hello world\x01"), []byte("hello world"), 4, nil},
		{[]byte("helloworld\x02\x02"), []byte("helloworld"), 3, nil},
		{[]byte("helloworld\x02\x02"), []byte("helloworld"), 4, nil},
		{[]byte("hello"), nil, 5, ErrInvalidPKCS7Padding},
		{[]byte("hello\x00\x03\x03"), nil, 4, ErrInvalidPKCS7Padding},
	}
	e1 := "unexpected error for item %d, %q: "
	e2 := "failed unpadding item %d, %q: "
	for n, el := range test {
		have, err := pkcs7Unpad(el.Input, el.BlockSize)
		if err != el.Err {
			t.Fatalf(e1+"want \"%v\", have \"%v\"",
				n, el.Input, el.Err, err)
		}
		if !bytes.Equal(have, el.Want) {
			t.Fatalf(e2+"want %q, have %q",
				n, el.Input, el.Want, have)
		}
	}
}
