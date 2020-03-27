package jwt

import (
	"fmt"
	"log"
	"testing"
	"time"
)

func TestBase64Encode(t *testing.T) {
	type User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Claims
	}

	secret := "secret"
	me := User{
		Username: "meeee",
		ID:       "shhh, it's a secret",
		Claims:   ClaimsWithExp(time.Minute * -1),
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

	fmt.Printf("%+v\n", testUser)
}
