# JWT Verification Demo

tested with go1.14 on macos

## Dependencies

1. 3rd libs:
    - "github.com/lestrrat-go" as the underlying lib to parse jwt/jwk
2. go 1.14 with go mod

## Features

1. parse JWK formated key from string: parseSigKey()
2. fetch JWKs from wellknown URL: fetchJWKSFromWellKnown()
3. JWT token verification: verifyAccessToken()
4. dump JWT token: dumpYuFuAT()
5. demo authn/authz middlewares:
    - authn()
    - authz()
