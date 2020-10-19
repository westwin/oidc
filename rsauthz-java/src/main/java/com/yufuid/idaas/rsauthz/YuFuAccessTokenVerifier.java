package com.yufuid.idaas.rsauthz;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

import java.text.ParseException;

public class YuFuAccessTokenVerifier extends DefaultJWTClaimsVerifier {
    private static final BadJWTException MISSING_AZP_CLAIM_EXCEPTION = new BadJWTException("missing azp claim");
    private static final BadJWTException MISSING_ISS_CLAIM_EXCEPTION = new BadJWTException("missing iss claim");
    private static final BadJWTException MISSING_SUB_CLAIM_EXCEPTION = new BadJWTException("missing sub claim");
    //private String aud;
    private final String iss;
    private final String azp;

    public YuFuAccessTokenVerifier(String iss, String azp, int clockSkew) {
        this.setMaxClockSkew(clockSkew);
        this.iss = iss;
        this.azp = azp;
    }

    @Override
    public void verify(final JWTClaimsSet claimsSet, final SecurityContext securityContext)
        throws BadJWTException {

        super.verify(claimsSet, securityContext);

        if (this.azp != null) {
            try {
                String azp = claimsSet.getStringClaim("azp");
                if (!this.azp.equals(azp)) {
                    throw new BadJWTException(
                        String.format("azp claim not match, expected: '%s', but: '%s'", this.azp, azp)
                    );
                }
            } catch (ParseException e) {
                throw MISSING_AZP_CLAIM_EXCEPTION;
            }
        }

        if (this.iss != null) {
            String iss = claimsSet.getIssuer();
            if (iss == null) {
                throw MISSING_ISS_CLAIM_EXCEPTION;
            }
            if (!this.iss.equals(iss)) {
                throw new BadJWTException(
                    String.format("iss claim not match, expected: '%s', but: '%s'", this.iss, iss)
                );
            }
        }
        /**
         if (this.aud != null) {
         for (String aud: claimsSet.getAudience()) {

         if (aud == null || aud.isEmpty()) {
         continue; // skip
         }

         if (expectedAudience.contains(new Audience(aud))) {
         audMatch = true;
         }
         }

         if (! audMatch) {
         throw new BadJWTException("Invalid JWT audience claim, expected " + expectedAudience);
         }
         }
         */

        if (claimsSet.getSubject() == null) {
            throw MISSING_SUB_CLAIM_EXCEPTION;
        }
    }
}

