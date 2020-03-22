package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultExpirationTime used as default expiration date value
const DefaultExpirationTime = time.Minute * 5

// Claims contains required fields
type Claims struct {
	// unix time
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// DefaultClaims return default claims
func DefaultClaims() Claims {
	iat := time.Now()
	exp := iat.Add(DefaultExpirationTime)

	return Claims{ExpiresAt: exp.Unix(), IssuedAt: iat.Unix()}
}

// base64Encode takes in a string and returns a base 64 encoded string
func base64Encode(src string) string {
	return strings.
		TrimRight(base64.URLEncoding.
			EncodeToString([]byte(src)), "=")
}

// base64Decode takes in a base 64 encoded string and
// returns the actual string or an error of it fails to decode the string
func base64Decode(src string) (string, error) {
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(src)
	if err != nil {
		errMsg := fmt.Errorf("Decoding Error %s", err)
		return "", errMsg
	}
	return string(decoded), nil
}

// hash generates a Hmac256 hash of a string using a secret
func generateHash(src, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(src))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// isValidhash validates a hash againt a value
func isValidhash(value string, h string, secret string) bool {
	return h == generateHash(value, secret)
}

// GenerateJWT generates a jwt.
func GenerateJWT(payload interface{}, secret string) (string, error) {
	type Header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	jsonHeader, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encodedHeader := base64Encode(string(jsonHeader))
	encodedPayload := base64Encode(string(jsonPayload))

	signatureValue := encodedHeader + "." + encodedPayload

	return signatureValue + "." + generateHash(signatureValue, secret), nil
}

// DecodeJWT decodes jwt, returns error if jwt is invalid, otherwise writes to payload
func DecodeJWT(jwt string, secret string, payload interface{}) error {
	token := strings.Split(jwt, ".")
	// check if the jwt token contains
	// header, payload and token
	if len(token) != 3 {
		splitErr := errors.New("Invalid token: token should contain header, payload and secret")
		return splitErr
	}
	// decode payload
	decodedPayload, err := base64Decode(token[1])
	if err != nil {
		return fmt.Errorf("Invalid payload: %s", err.Error())
	}
	// payload := Payload{}
	// parses payload from string to a struct
	err = json.Unmarshal([]byte(decodedPayload), payload)
	if err != nil {
		return fmt.Errorf("Invalid payload: %s", err.Error())
	}
	// checks if the token has expired.
	// if payload.Exp != 0 && time.Now().Unix() > payload.Exp {
	// 	return errors.New("Expired token: token has expired")
	// }
	// signatureValue := token[0] + "." + token[1]
	// // verifies if the header and signature is exactly whats in
	// // the signature
	// if CompareHmac(signatureValue, token[2], secret) == false {
	// 	return errors.New("Invalid token")
	// }

	return nil
}
