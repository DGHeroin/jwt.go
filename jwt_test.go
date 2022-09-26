package jwt

import (
    "testing"
)

func TestNewJWT(t *testing.T) {
    sign, verify := NewJTW("hello", SigningMethodHS256)
    token, _ := sign(map[string]interface{}{"name": "hello", "address": "world"})
    t.Log(token)

    var output map[string]interface{}
    ok := verify(token, &output)
    t.Log("verify:", ok, output)
}
func BenchmarkJWTSign(b *testing.B) {
    sign, _ := NewJTW("hello", SigningMethodHS256)

    for i := 0; i < b.N; i++ {
        sign(map[string]interface{}{"name": "hello", "address": "world"})
    }
}

func BenchmarkJWTVerify(b *testing.B) {
    sign, verify := NewJTW("hello", SigningMethodHS256)
    token, _ := sign(map[string]interface{}{"name": "hello", "address": "world"})

    for i := 0; i < b.N; i++ {
        var output map[string]interface{}
        verify(token, &output)
    }
}
