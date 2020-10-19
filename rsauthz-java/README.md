# Demo for Resource Server Authorization

The code will demo the [Authorization Flow](https://docs.qq.com/doc/DSEN0SlhZWWFJSHR4), includes:  

1. how to parse signature key as JWK format
2. how to verify the access_token as a JWT token
3. how to extract user identity from access_token

## Dependencies

1. JDK 1.8
2. nimbus-jose-jwt 7.1

## How to Run

1. find the main() in Main.java
2. contact YuFu admin to get the .well-known URL and other necessary params