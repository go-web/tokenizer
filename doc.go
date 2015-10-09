// Package tokenizer provides encoding for tokens that can carry user data.
//
// Tokens are made up of base64url(iv,aes(pkcs7(ts,data)),hmac)
// where the iv is random, and hmac signs iv,aes(...).
package tokenizer
