package jwt

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// DefaultExpirationTime used as default expiration date value
const DefaultExpirationTime = time.Minute * 5

var (
	// ErrTokenExpired token expired
	ErrTokenExpired = errors.New("Token expired")

	// ErrTokenFormInvalid token form invalid
	ErrTokenFormInvalid = errors.New("Token form invalid")

	// ErrTokenFormatNotSupported token format not supported
	// This package only supports HS256 encoding
	ErrTokenFormatNotSupported = errors.New("Token format not supported")

	// ErrSignatureInvalid token hash does not match body
	// Signature does not match the payload
	ErrSignatureInvalid = errors.New("Token hash does not match body")

	// ErrClaimsInvalid token claims invalid
	// Conflicts inside claims, such as iat > exp
	ErrClaimsInvalid = errors.New("Token claims invalid")

	// ErrUnmarshalTargetNotPointer target must be a pointer
	// Unmarshal must be used with a pointer
	ErrUnmarshalTargetNotPointer = errors.New("Unmarshal target must be a pointer")
)

// Header first part of jwt
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// defaultHeader default and the only supported header type
func defaultHeader() Header {
	return Header{
		Alg: "HS256",
		Typ: "JWT",
	}
}

// Generate generates a jwt.
func Generate(payload interface{}, secret string) (string, error) {

	header := defaultHeader()

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

// Unmarshal unmarshals into target, returns error if jwt is invalid
func Unmarshal(token string, secret string, target interface{}) error {
	if !isPointer(target) {
		return ErrUnmarshalTargetNotPointer
	}

	if err := IsValid(token, secret); err != nil {
		return err
	}

	body := strings.Split(token, ".")[1]
	bodyDecoded, err := base64Decode(body)
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(bodyDecoded), target)
}

// IsValid checks token for validity, expiration time
func IsValid(token, secret string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrTokenFormInvalid
	}

	if err := checkHeader(parts[0]); err != nil {
		return err
	}

	if err := checkPayload(parts[1]); err != nil {
		return err
	}

	body := parts[0] + "." + parts[1]
	if !checkSignature(parts[2], body, secret) {
		return ErrSignatureInvalid
	}

	return nil
}

// checkSignature validates a hash againt a value
func checkSignature(hash, body, secret string) bool {
	return hash == generateHash(body, secret)
}

func checkPayload(c string) error {
	claimsString, err := base64Decode(c)
	if err != nil {
		return err
	}

	claims := DefaultClaims{}
	err = json.Unmarshal([]byte(claimsString), &claims)
	if err != nil {
		return err
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return ErrTokenExpired
	}

	if claims.IssuedAt > claims.ExpiresAt {
		return ErrClaimsInvalid
	}

	return nil
}

func checkHeader(headerEncoded string) error {
	headerString, err := base64Decode(headerEncoded)
	if err != nil {
		return err
	}

	header := Header{}
	err = json.Unmarshal([]byte(headerString), &header)
	if err != nil {
		return err
	}

	if header != defaultHeader() {
		return ErrTokenFormatNotSupported
	}

	return nil
}
