package main

import (
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
)

func main() {
	s := g.Server()
	s.SetPort(8000)

	s.BindHandler("/", func(r *ghttp.Request) {
		r.Response.CORSDefault()
		r.Response.Write("hello world")
		r.SetParam()
	})

	s.Group("/api.v2", func(group *ghttp.RouterGroup) {
		group.Middleware(nil)
	})

	s.Run()
}
