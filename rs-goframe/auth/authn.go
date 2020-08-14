package auth

import (
	"github.com/gogf/gf/net/ghttp"
)

func MiddlewareAuthn(r *ghttp.Request) {

}

func MiddlewareAuthnWithOptions(options AuthnOptions) func(r *ghttp.Request) {
	return nil
}

type AuthnOptions struct {
}
