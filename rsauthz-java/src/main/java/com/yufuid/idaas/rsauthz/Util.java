package com.yufuid.idaas.rsauthz;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;

public class Util {
    /**
     * load the signature public key from jwks uri
     * NOTE: the public key should be cached in production
     *
     * @param uri The JWK set URL. Must not be {@code null}.
     */
    public static JWKSet loadSigKeyFromURL(final String uri) {
        return loadSigKeyFromURL(uri, 0, 0, 0);
    }

    /**
     * @param uri            The JWK set URL. Must not be {@code null}.
     * @param connectTimeout URL connection timeout, in milliseconds. If zero no (infinite) timeout.
     * @param readTimeout    The URL read timeout, in milliseconds. If zero no (infinite) timeout.
     * @param sizeLimit      The read size limit, in bytes. If zero no limit.
     */
    public static JWKSet loadSigKeyFromURL(
        final String uri,
        final int connectTimeout,
        final int readTimeout,
        final int sizeLimit
    ) {
        // Load JWK set from URL
        try {
            JWKSet publicKeys = JWKSet.load(new URL(uri), connectTimeout, readTimeout, sizeLimit);
            return publicKeys;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * parse the public key from raw string(JWK format)
     *
     * @param raw
     */
    public static JWKSet parseSigKeyFromString(final String raw) {
        try {
            JWKSet publicKeys = JWKSet.parse(raw);
            return publicKeys;
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void dumpPublicKeys(JWKSet publicKeys) {
        if (publicKeys == null) {
            System.err.println("null public keys");
        }

        for (JWK k : publicKeys.getKeys()) {
            System.out.println(k);
        }
    }

    /**
     * verify and parse the access_token as a JWT token
     *
     * @param accessToken
     */
    public static JWTClaimsSet verifyAndDumpAccessToken(
        final String accessToken,
        final JWKSet publicKeys,
        final String iss,
        final String azp,
        final int clockSkew
    ) throws
        ParseException,
        JOSEException,
        BadJOSEException {
        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
            new DefaultJWTProcessor<>();

        // The expected JWS algorithm of the access tokens (for IEG this can be hardcoded to RS256)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public RSA keys
        JWSKeySelector<SecurityContext> keySelector =
            new JWSVerificationKeySelector<>(expectedJWSAlg, new ImmutableJWKSet<>(publicKeys));
        jwtProcessor.setJWSKeySelector(keySelector);

        // Set the required JWT claims for access tokens issued by YuFu

        jwtProcessor.setJWTClaimsSetVerifier(new YuFuAccessTokenVerifier(iss, azp, clockSkew));
        // Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, ctx);

        return claimsSet;
    }
}
