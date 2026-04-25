# Tokenizer

The tokenizer package provides encoding for tokens that can carry user
data in a secure way.

Tokens generated with this tokenizer consist of:

	token = base64url(version,iv,aes(pkcs7(ts,data)),hmac)

The leading version byte (currently `1`) lets future versions reject
older formats. All tokens embed the creation time and return it on
decode. Time is in UTC with 1 second precision, stored as a uint32 unix
timestamp; values overflow after 2106-02-07T06:28:15Z.

[![GoDoc](https://godoc.org/github.com/go-web/tokenizer?status.svg)](https://godoc.org/github.com/go-web/tokenizer)
[![CI](https://github.com/go-web/tokenizer/actions/workflows/ci.yml/badge.svg)](https://github.com/go-web/tokenizer/actions/workflows/ci.yml)

## Usage

Download:

	go get github.com/go-web/tokenizer

See the [example](./example_test.go) for details.
