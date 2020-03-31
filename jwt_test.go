package jwt

import (
	"log"
	"testing"
	"time"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	DefaultClaims
}

func TestBase64Encode(t *testing.T) {

	secret := "secret"
	me := User{
		Username:      "meeee",
		ID:            "shhh, it's a secret",
		DefaultClaims: DefaultClaimsWithExp(time.Minute),
	}

	token, err := Generate(me, secret)
	if err != nil {
		log.Fatal(err)
	}

	testUser := User{}
	err = Unmarshal(token, secret, &testUser)
	if err != nil {
		log.Fatal(err)
	}

	if testUser != me {
		t.Errorf("Expected %+v to equal %+v", me, testUser)
	}
}
