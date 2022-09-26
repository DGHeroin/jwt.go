package jwt

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/base64"
    "encoding/json"
    "strconv"
    "strings"
)

// header.payload.signature
const (
    SigningMethodHS256 = 256
    SigningMethodHS384 = 384
    SigningMethodHS512 = 512
)

func NewJTW(secret string, signType int) (func(interface{}) (string, error), func(string, interface{}) bool) {
    header, _ := json.Marshal(map[string]interface{}{"alg": "HS" + strconv.Itoa(signType), "typ": "JWT"})
    return func(jsonBindObject interface{}) (string, error) {
            payload, err := json.Marshal(jsonBindObject)
            if err != nil {
                return "", err
            }
            signature := HashHMAC(signType, string(header)+string(payload), secret)
            return base64encode(header) + "." + base64encode(payload) + "." + base64encode(signature), nil
        },
        func(s string, jsonBindObject interface{}) (ok bool) {
            strs := strings.Split(s, ".")
            if len(strs) < 3 {
                return
            }
            headerStr, payloadStr, signatureStr := strs[0], strs[1], strs[2]
            header, err := base64decode(headerStr)
            if err != nil {
                return
            }
            payload, err := base64decode(payloadStr)
            if err != nil {
                return
            }
            signature := HashHMAC(signType, string(header)+string(payload), secret)
            if base64encode(signature) != signatureStr {
                return
            }

            ok = json.Unmarshal(payload, jsonBindObject) == nil
            return
        }
}
func HashHMAC(signType int, data string, secret string) []byte {
    var fn = sha256.New
    switch signType {
    case SigningMethodHS256:
        fn = sha256.New
    case SigningMethodHS384:
        fn = sha512.New384
    case SigningMethodHS512:
        fn = sha512.New
    }
    h := hmac.New(fn, []byte(secret))
    h.Write([]byte(data))
    return h.Sum(nil)
}
func base64encode(data []byte) string {
    return base64.RawURLEncoding.EncodeToString(data)
}
func base64decode(str string) ([]byte, error) {
    return base64.RawURLEncoding.DecodeString(str)
}
