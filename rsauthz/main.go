package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

var (
	addr = ":9999"
)

func main() {
	_, err := parseSigKey()
	if err != nil {
		fmt.Printf("parse sig key err: %v\n", err)
	}

	_, err = fetchJWKSFromWellKnown()
	if err != nil {
		fmt.Printf("parse sig key err: %v\n", err)
	}

	yufuAT, err := verifyAccessToken()
	if err != nil {
		fmt.Printf("err verifying access_token: %v\n", err)
		return
	}

	dumpYuFuAT(yufuAT)

	// demo handlers protected by authn
	// public resource
	http.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "welcome, please login")
	})

	// authz: only allowed with the perm of "read:todos"
	http.Handle("/api/todos",
		authn(authz(permReadTodo, http.HandlerFunc(listTodos))))

	http.ListenAndServe(":9999", nil)
}

func listTodos(w http.ResponseWriter, r *http.Request) {
	todos := []struct {
		Name string    `json:"name"`
		When time.Time `json:"when"`
	}{
		{
			Name: "Meeting with boss",
			When: time.Now().Add(2 * time.Hour),
		},
		{
			Name: "Shopping with wife",
			When: time.Now().Add(4 * time.Hour),
		},
		{
			Name: "Dinner with daughter",
			When: time.Now().Add(8 * time.Hour),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(todos); err != nil {
		fmt.Fprintf(w, err.Error())
	}
}

const (
	// context key for perms of an authenticated subject
	contextKeyPerm = "perms"

	// wildcard perm which can do anything
	permDoAnything = "*:*"
	permReadTodo   = "read:todos"
)

// the authentication middleware to verify the access_token issued by AS
func authn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// extract the access_token as a Bearer token
		s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 {
			http.Error(w, "Not authorized.", http.StatusUnauthorized)
			return
		}

		// todo, verify the access_token
		at := s[1]
		log.Printf("access_token is: '%s'\n", at)

		// todo, extract the perms and propogate into context
		p := []string{
			permDoAnything,
		}
		ctx := context.WithValue(r.Context(), contextKeyPerm, perms(p))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// the authorization middleware to verify the perms
func authz(needs string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		v := r.Context().Value(contextKeyPerm)

		if v == nil {
			http.Error(w,
				fmt.Sprintf("Access Denied. Needs: '%s', Got: '%v'\n", needs, ""),
				http.StatusForbidden)
			return
		}

		p := v.(perms)
		if !p.grant(needs) {
			http.Error(w,
				fmt.Sprintf("Access Denied. Needs: '%s', Got: '%v'\n", needs, p),
				http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type perms []string

var (
	permsGuest = perms([]string{})
)

func (p perms) grant(needs string) bool {
	for _, v := range p {
		if v == needs || v == permDoAnything {
			return true
		}
	}

	return false
}

// parse sig key from raw string
// NOTE: this SHOULD be cached
func parseSigKey() (*jwk.Set, error) {
	// this is the RSA public key which will be retrieved from YuFu
	// and will be used to verify the signature of access_token
	raw := `
{
	"kty": "RSA",
	"e": "AQAB",
	"use": "sig",
	"kid": "ai-ce11f471f42a45188e63debbbf06a039:sso",
	"alg": "RS256",
	"n": "-kI6t2uh_D-LdPqOwKQHI3o2ytZA-lDcYXR6ePxkWbGV3XFSLspIqzn6gpV9JJRzhkYYrcMlWgxdvCGsnir5a9zSTBXgv0RTyoeGu8EIPeNGsOk8rDlnbs23wqGdYJyiPgUmYR1LBjpDordUEc3nxHZWkzUGHyWpbkJUc6vVwzlaem_v8IuMALY7p47dpon6xgc5pIUwzuM7ecYBF1yLf_VQzCaHc7cBGS1xv0SZEimzqPTuL3AhaNt-7he_fQD_NKqMCTBNjCxxQePpRoADHp9-cjsGhaUAzHBZ935NWrXquZ6CPdyZdKN5v4ZfbkxLxYyx2muNY7vUN4RSxM0b9w"
	}
`
	jwks, err := jwk.ParseString(raw)
	if err != nil {
		return nil, err
	}

	k := jwks.LookupKeyID("ai-ce11f471f42a45188e63debbbf06a039:sso")[0]
	fmt.Printf("kty: %v, alg: %s, kid: %s, use: %s\n", k.KeyType(), k.Algorithm(), k.KeyID(), k.KeyUsage())

	return jwks, nil
}

// fetch key from wellknown endpoint.
// NOTE: this SHOULD be cached
func fetchJWKSFromWellKnown() (*jwk.Set, error) {
	// this can be retrived from YuFu
	wellknownURL := "https://xifeng-idp.i.yufuid.com/sso/tn-0a5a283e76074b23a532c99f6c3a81b9/ai-ce11f471f42a45188e63debbbf06a039/oidc/jwks.json"
	jwks, err := jwk.Fetch(wellknownURL)

	if err != nil {
		return nil, err
	}

	k := jwks.LookupKeyID("ai-ce11f471f42a45188e63debbbf06a039:sso")[0]
	fmt.Printf("kty: %v, alg: %s, kid: %s, use: %s\n", k.KeyType(), k.Algorithm(), k.KeyID(), k.KeyUsage())

	return jwks, nil
}

func verifyAccessToken() (jwt.Token, error) {
	rawAccessToken := "eyJraWQiOiJhaS1jZTExZjQ3MWY0MmE0NTE4OGU2M2RlYmJiZjA2YTAzOTpzc28iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmZW5neGlAeXVmdWlkLmNvbSIsImFwcF9pbnN0YW5jZV9pZCI6ImFpLWNlMTFmNDcxZjQyYTQ1MTg4ZTYzZGViYmJmMDZhMDM5IiwiaXNzIjoiaHR0cHM6XC9cL3hpZmVuZy1pZHAuaS55dWZ1aWQuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZmVuZ3hpQHl1ZnVpZC5jb20iLCJub25jZSI6Im5vbmNlLWI0cXE2YnFjc3B3YzZnd2lrc3R3MmpmamEiLCJhdWQiOiJtZWV0aW5nLWFwaSIsIm5iZiI6MTU5NzM4OTUyNSwidXNlcl9pZCI6InVzLTY4YmU1MDMzZmIzMTQ0OWZiOTdiY2NkYzQ5M2Y4NmRiIiwiYXpwIjoiYWktY2UxMWY0NzFmNDJhNDUxODhlNjNkZWJiYmYwNmEwMzkiLCJ0bnRfaWQiOiJ0bi0wYTVhMjgzZTc2MDc0YjIzYTUzMmM5OWY2YzNhODFiOSIsInBlcm1zIjpbInI6bWVldGluZyIsInc6bWVldGluZyJdLCJleHAiOjE1OTczOTEzMjUsImlhdCI6MTU5NzM4OTUyNSwiZW1haWwiOiJmZW5neGlhc2RAeXVmdWlkLmNvbSJ9.Nl0YJ6-5TOE82uLDTST-Ioe1w8mMOwXOmkldSbFgOfGIxfWpp72Xm3KH9Sc0J-zQpF9LqHN4QDPFOLSkJUmiOlgsj8WZEOZzZaLxhPBzPdARxszGOA523LRQ_y9f85w8EfC2fAIV1L7uC1SiE93-70Yy9OkQzNsNX5SGyEFWc21-cM2J8CXSE2btXBTetx39cGl60HRvssihCFGb4U9uqnN9IyVDBvPfadP11gSyUjt6tFCAHBaQ_5lolIBQSd5HUyxtMg0ib5M3emv2kd-NjDZGFNslTuCu2muDWnFRskGSqVh_6LYR3YHtsgckhNoESz4K6FnIDNCSfAzzIUUDHg"

	jwks, _ := parseSigKey()
	yufuAT, err := jwt.ParseString(rawAccessToken, jwt.WithKeySet(jwks), jwt.WithOpenIDClaims())
	if err != nil {
		return nil, err
	}

	fmt.Printf("aud: %v\n", yufuAT.Audience())

	checkers := []func() error{
		func() error {
			return jwt.Verify(yufuAT, jwt.WithAudience("meeting-api"))
		},

		func() error {
			return jwt.Verify(yufuAT, jwt.WithIssuer("https://xifeng-idp.i.yufuid.com"))
		},

		func() error {
			// must be the client_id of IEG-Gateway
			return jwt.Verify(yufuAT, jwt.WithClaimValue("azp", "ai-ce11f471f42a45188e63debbbf06a039"))
		},

		func() error {
			/*
				NOTE: this check might fail, as the rawAccessToken might be already expired
			*/
			clockSkew := 2 * time.Minute
			return jwt.Verify(yufuAT, jwt.WithClock(jwt.ClockFunc(time.Now)),
				jwt.WithAcceptableSkew(clockSkew),
			)
		},

		// only check access_token contains a perms claim
		func() error {
			v, ok := yufuAT.Get("perms")
			if !ok {
				return fmt.Errorf("missing claim of perms")
			}
			p, ok := v.([]interface{})
			if !ok {
				return fmt.Errorf("invalid type of perms, expects: []interface{}")
			}
			fmt.Printf("perms: '%v'\n", p)

			return nil
		},
	}

	for _, ch := range checkers {
		if err := ch(); err != nil {
			return nil, err
		}
	}

	return yufuAT, nil
}

func dumpYuFuAT(yufuAT jwt.Token) {
	m, err := yufuAT.AsMap(context.Background())
	if err != nil {
		fmt.Printf("dump yufu access_token err: %v\n", err)
		return
	}

	fmt.Println("dumping yufu access_token")
	for k, v := range m {
		fmt.Printf("%s:  %v\n", k, v)
	}
}

func includes(candidates []string, looking string) bool {
	if len(candidates) == 0 {
		return false
	}
	for _, v := range candidates {
		if v == looking {
			return true
		}
	}
	return false
}
