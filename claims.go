package jwt

import "time"

// DefaultClaims contains required fields
type DefaultClaims struct {
	// unix time
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// DefaultClaimsWithDefaultExp return claims with default expiration time
func DefaultClaimsWithDefaultExp() DefaultClaims {
	iat := time.Now()
	exp := iat.Add(DefaultExpirationTime)

	return DefaultClaims{ExpiresAt: exp.Unix(), IssuedAt: iat.Unix()}
}

// DefaultClaimsWithExp return claims with custom expiration time
func DefaultClaimsWithExp(duration time.Duration) DefaultClaims {
	iat := time.Now()
	exp := iat.Add(duration)

	return DefaultClaims{ExpiresAt: exp.Unix(), IssuedAt: iat.Unix()}
}
