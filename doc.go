// Package tokenizer provides encoding for tokens that can carry user data.
//
// Tokens are made up of base64url(version,iv,aes(pkcs7(ts,data)),hmac)
// where version is a single byte format marker, iv is random, and hmac
// signs version,iv,aes(...).
package tokenizer
