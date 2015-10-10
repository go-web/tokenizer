# Tokenizer

The tokenizer package provides encoding for tokens that can carry user
data in a secure way.

Tokens generated with this tokenizer consist of:

	token = base64url(iv,aes(pkcs7(ts,data)),hmac)

All tokens embed the time they were created, and that information is
available when the token is decoded. Time is always in UTC, with 1s
precision.

[![GoDoc](https://godoc.org/github.com/go-web/tokenizer?status.svg)](https://godoc.org/github.com/go-web/tokenizer)

[![Build Status](https://secure.travis-ci.org/go-web/tokenizer.png)](http://travis-ci.org/go-web/tokenizer)

## Usage

Download:

	go get github.com/go-web/tokenizer

See the [example](./example_test.go) for details.
