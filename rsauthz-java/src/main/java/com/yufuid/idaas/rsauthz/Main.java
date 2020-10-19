package com.yufuid.idaas.rsauthz;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * this is a demo:
 * as a resource server, how to verify the access_token issued by YuFu which as an authorization server.
 * <p>
 * after the verification, the resource server can get below information:
 * <ul>
 * <li>user identity: user id and tenant id</li>
 * <li>user basic profile: username, email address etc</li>
 * <li>permissions: all permissions(managed by YuFu) this user have in this resource server</li>
 * </ul>
 */
public class Main {
   public static void main(String[] args) throws Throwable {
      /**
       * load signature public key from jwks uri
       */
      // replace me
      String
          jwksURI =
          "https://xifeng-idp.i.yufuid.com/sso/tn-0a5a283e76074b23a532c99f6c3a81b9/ai-ce11f471f42a45188e63debbbf06a039/oidc/jwks.json";
      Util.dumpPublicKeys(Util.loadSigKeyFromURL(jwksURI));

      /**
       * parse signature public key from raw string
       */
      // replace me
      String
          jwksRaw =
          "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"ai-ce11f471f42a45188e63debbbf06a039:sso\",\"alg\":\"RS256\",\"n\":\"-kI6t2uh_D-LdPqOwKQHI3o2ytZA-lDcYXR6ePxkWbGV3XFSLspIqzn6gpV9JJRzhkYYrcMlWgxdvCGsnir5a9zSTBXgv0RTyoeGu8EIPeNGsOk8rDlnbs23wqGdYJyiPgUmYR1LBjpDordUEc3nxHZWkzUGHyWpbkJUc6vVwzlaem_v8IuMALY7p47dpon6xgc5pIUwzuM7ecYBF1yLf_VQzCaHc7cBGS1xv0SZEimzqPTuL3AhaNt-7he_fQD_NKqMCTBNjCxxQePpRoADHp9-cjsGhaUAzHBZ935NWrXquZ6CPdyZdKN5v4ZfbkxLxYyx2muNY7vUN4RSxM0b9w\"}]}";
      JWKSet jwks = Util.parseSigKeyFromString(jwksRaw);
      Util.dumpPublicKeys(jwks);

      /**
       * parse access_token
       */
      // replace me, NOTE: this might fail, as the token already expired
      String accessToken =
         "eyJraWQiOiJhaS1jZTExZjQ3MWY0MmE0NTE4OGU2M2RlYmJiZjA2YTAzOTpzc28iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1cy02OGJlNTAzM2ZiMzE0NDlmYjk3YmNjZGM0OTNmODZkYiIsImlzcyI6Imh0dHBzOlwvXC94aWZlbmctaWRwLmkueXVmdWlkLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6ImZlbmd4aUB5dWZ1aWQuY29tIiwiYXVkIjoiSUVHX1RPQiIsIm5iZiI6MTYwMzEwODQ4MywidXNlcl9pZCI6InVzLTY4YmU1MDMzZmIzMTQ0OWZiOTdiY2NkYzQ5M2Y4NmRiIiwiYXpwIjoiYWktY2UxMWY0NzFmNDJhNDUxODhlNjNkZWJiYmYwNmEwMzkiLCJ0bnRfaWQiOiJ0bi0wYTVhMjgzZTc2MDc0YjIzYTUzMmM5OWY2YzNhODFiOSIsIm5hbWUiOiJGZW5nWGkiLCJwZXJtcyI6WyJcL2J1c2luZXNzXC9yZW1vdmUtYnVzaW5lc3MiLCJcL2NvbW1lcmNpYWxcL2ZpbmQtY29tbWVyY2lhbCIsIlwvYnVzaW5lc3NcL2FkbWluXC9hZGQtYnVzaW5lc3MiLCJcL2F0dGFjaG1lbnRcL3VwbG9hZCIsIlwvYnVzaW5lc3NcL3VwZGF0ZS1idXNpbmVzcyIsIlwvYnVzaW5lc3NcL2FkbWluXC91cGRhdGUtYnVzaW5lc3MiLCJcL2J1c2luZXNzXC9hZG1pblwvcmV2aWV3LWJ1c2luZXNzLWJhdGNoIiwiXC9jb21tZXJjaWFsXC9maW5kLWJ1c2luZXNzLWxpc3QiLCJcL2NvbW1lcmNpYWxcL2ZpbmQtYmluZC1jb21tZXJjaWFsLWxpc3QiLCJcL2J1c2luZXNzXC9hZG1pblwvZmluZC1idXNpbmVzcy1saXN0IiwiXC9hY2NvdW50XC9hZG1pblwvZmluZC1hY2NvdW50LWluZm8iLCJcL2J1c2luZXNzXC9hZG1pblwvZGVhY3RpdmF0ZS1idXNpbmVzcyIsIlwvYXR0YWNobWVudFwvZG93bmxvYWQiLCJcL2J1c2luZXNzXC9hZGQtYnVzaW5lc3MiLCJcL2J1c2luZXNzXC9maW5kLWJ1c2luZXNzIiwiXC9jb21tZXJjaWFsXC9hZGQtY29tbWVyY2lhbCIsIlwvY29tbWVyY2lhbFwvZmluZC1iaW5kLWJ1c2luZXNzLWxpc3QiLCJcL2J1c2luZXNzXC9hZG1pblwvZmluZC1idXNpbmVzcyIsIlwvYnVzaW5lc3NcL2ZpbmQtYnVzaW5lc3MtbGlzdCIsIlwvYWNjb3VudFwvYWRtaW5cL3JlbW92ZS1hZG1pbi10by1jb21tZXJjaWFsIiwiXC9hY2NvdW50XC9hZG1pblwvcmVtb3ZlLWNvbW1lcmNpYWwiLCJcL2J1c2luZXNzXC9saXN0LW9wdGlvbiJdLCJleHAiOjE2MDMxMTU2ODMsImlhdCI6MTYwMzEwODQ4MywianRpIjoiZjc2NWZhZWUtM2UwOS00NTI3LTkzZGItMGIyNTkzNDFmMWEwIn0.uPRqOgETQWEQxVX_37OmvH2U0nvJIwK8q9ffww4bo-U6-o456NLwHURZ-oSalN8oV7jPf4ubrqRp3oIHr81EX9hsXo2T5IHYhzUar2uKJyxVdNIfHo7p0dJlOU4Yl5gd7uPPzFrbJSfGT_Im1ui80z1JJfBkR2jlYVTSmjcC9DWtOJ6bMV867N5pOqr4HEWwBHYNmwr8XVp71UnnMC0oma-0nb2omgZONXQAEDAqhkb5KNTY9EefgcqyANuJjDjAfg_vMUGYzNNO5oJ0jSCGC_KzwNlvUeoeU1t-RVDbY-L30HKiLC6z1cHbwSBdrWaC6Adv0xdk2dcxqksMWHvNZA";
      String iss = "https://xifeng-idp.i.yufuid.com";
      String azp = "ai-ce11f471f42a45188e63debbbf06a039";
      int clockSkew = 60; // in seconds
      JWTClaimsSet claims = Util.verifyAndDumpAccessToken(accessToken, jwks, iss, azp, clockSkew);

      // Print out the token claims set
      System.out.println(claims.toJSONObject());

      // core claims
      System.out.printf("user id: '%s'\n", claims.getSubject());
      System.out.printf("tenant id: '%s\n'", claims.getStringClaim("tnt_id"));
      System.out.printf("username: '%s'\n", claims.getStringClaim("preferred_username"));
      System.out.printf("user display name: '%s'\n", claims.getStringClaim("name"));

      System.out.println("dumping perms:");
      String[] perms = claims.getStringArrayClaim("perms");
      for (String perm: perms) {
         System.out.printf("perms: '%s'\n", perm);
      }
   }
}
