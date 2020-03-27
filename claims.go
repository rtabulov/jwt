package jwt

import "time"

// Claims contains required fields
type Claims struct {
	// unix time
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// ClaimsWithDefaultExp return claims with default expiration time
func ClaimsWithDefaultExp() Claims {
	iat := time.Now()
	exp := iat.Add(DefaultExpirationTime)

	return Claims{ExpiresAt: exp.Unix(), IssuedAt: iat.Unix()}
}

// ClaimsWithExp return claims with custom expiration time
func ClaimsWithExp(duration time.Duration) Claims {
	iat := time.Now()
	exp := iat.Add(duration)

	return Claims{ExpiresAt: exp.Unix(), IssuedAt: iat.Unix()}
}
