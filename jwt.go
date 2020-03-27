package jwt

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
)

// DefaultExpirationTime used as default expiration date value
const DefaultExpirationTime = time.Minute * 5

var (
	// ErrTokenExpired token expired
	ErrTokenExpired = errors.New("Token expired")
	// ErrTokenFormInvalid token expired
	ErrTokenFormInvalid = errors.New("Token form invalid")
	// ErrTokenFormatNotSupported token expired
	ErrTokenFormatNotSupported = errors.New("Token format not supported")
	// ErrTokenHashInvalid token expired
	ErrTokenHashInvalid = errors.New("Token hash does not match body")
	// ErrClaimsInvalid token expired
	ErrClaimsInvalid = errors.New("Token claims invalid")
	// ErrUnmarshalTargetNotPointer token expired
	ErrUnmarshalTargetNotPointer = errors.New("Unmarshal target must be a pointer")
)

// Header first part of jwt
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

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

func isPointer(x interface{}) bool {
	return reflect.ValueOf(x).Kind() == reflect.Ptr
}

// Unmarshal unmarshals into target, returns error if jwt is invalid
func Unmarshal(token string, secret string, target interface{}) error {
	if !isPointer(target) {
		return ErrUnmarshalTargetNotPointer
	}

	if err := isValid(token, secret); err != nil {
		return err
	}

	body := strings.Split(token, ".")[1]
	bodyDecoded, err := base64Decode(body)
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(bodyDecoded), target)
}

// hashMatches validates a hash againt a value
func hashMatches(hash, payloadEncoded, secret string) bool {
	return hash == generateHash(payloadEncoded, secret)
}

// isValid checks token for validity, expiration time
func isValid(token, secret string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrTokenFormInvalid
	}

	if err := checkHeader(parts[0]); err != nil {
		return err
	}

	if err := checkClaims(parts[1]); err != nil {
		return err
	}

	if !hashMatches(parts[2], parts[0]+"."+parts[1], secret) {
		return ErrTokenHashInvalid
	}

	return nil
}

func checkClaims(c string) error {
	claimsString, err := base64Decode(c)
	if err != nil {
		return err
	}

	claims := Claims{}
	err = json.Unmarshal([]byte(claimsString), &claims)
	if err != nil {
		return err
	}

	// if claims != defaultHeader() {
	// 	return ErrTokenFormatNotSupported
	// }
	now := time.Now().Unix()
	if now > claims.ExpiresAt {
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
