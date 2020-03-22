package jwt

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"
)

func TestBase64Encode(t *testing.T) {
	type User struct {
		Username string `json:"username"`
		Claims
	}

	me := User{Username: "meeee", Claims: DefaultClaims()}

	const secret = "secret"
	token, err := GenerateJWT(me, secret)
	if err != nil {
		log.Fatal(err)
	}

	js, _ := json.Marshal(me)
	fmt.Printf("%+s\n", js)
	fmt.Println(token)

}
