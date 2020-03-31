package jwt

import "reflect"

func isPointer(x interface{}) bool {
	return reflect.ValueOf(x).Kind() == reflect.Ptr
}
