# AS Protected RS

## Overview

This is a demo for Authorization Server protected resource server(aka RS or API server).

This server protectes its resource(API) by consuming/trusting the access_token issued by the AS.

AS and RS builds the trust with a pre-shared secret(either asymmetric or symmetric).
The access_token is a JWT token signed by this secret, either with RS256 or HS256

From the payload of the access_token, RS can tell:

1. sub: identity of the principal, it can be a person or a bot
2. aud: whom the access_token was issued to, usually it's the id(or FQDN) of the RS
3. iss: who issued the access_token, usually it's the id(or FQDN) of the AS
4. perms: the granted permissions for the sub

## How to Run

1. go run main.go

## Terms

1. AS: Authorization Server
2. RS: Resource Server, or API Server
