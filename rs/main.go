package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	addr = ":8888"
)

func main() {
	args := os.Args[1:]
	addr = ":8888"
	if len(args) == 1 {
		addr = ":" + args[0]
	}
	fmt.Printf("Listening on %s\n", addr)

	// demo handlers protected by authn

	// public resource
	http.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "welcome, please login")
	})

	// authz: only allowed with the perm of "read:todos"
	http.Handle("/api/todos",
		authn(authz(permReadTodo, http.HandlerFunc(listTodos))))

	// protected resource, dump the access_token
	http.Handle("/api/token", authn(http.HandlerFunc(parseToken)))

	// protected resource, call AS api to return userinfo with access_token
	http.Handle("/api/userinfo", authn(http.HandlerFunc(userinfo)))

	http.ListenAndServe(addr, nil)
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

func parseToken(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "token info, todo")
}

func userinfo(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "user info, todo")
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
			doAnythingPerm,
		}
		ctx := context.WithValue(r.Context(), contextKeyPerm, perms(p))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// the authorization middleware to verify the perms
func authz(needs string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func (p perms) grant(needs string) bool {
	for _, v := range p {
		if v == needs || v == permDoAnything {
			return true
		}
	}

	return false
}
