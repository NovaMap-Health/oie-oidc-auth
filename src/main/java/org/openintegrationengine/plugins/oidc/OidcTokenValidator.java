/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.net.URL;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Full JOSE validation of a provider-signed token: signature against the
 * provider's JWKS, an asymmetric-only algorithm allowlist (kills alg=none and
 * HS256 key confusion), issuer, and an exp/nbf/iat freshness window with
 * configured skew. {@link #validate(String)} adds the ID-token audience rules;
 * {@link #validateAccessToken(String)} adds the rules for a JWT access token
 * presented to this engine as a resource server (RFC 9068).
 *
 * <p>The JWK source is held for the lifetime of this validator (one validator
 * per config load), so JWKS fetches are cached across logins with the
 * configured TTL, and an unknown {@code kid} triggers one rate-limited refetch
 * instead of a fetch per login.</p>
 */
public final class OidcTokenValidator {

    /** Same bounds as discovery: a key set is kilobytes, and a cloud provider is not 500 ms away. */
    private static final int JWKS_TIMEOUT_MILLIS = 10_000;
    private static final int JWKS_MAX_BYTES = 1024 * 1024;
    /** An unknown kid refetches at most this often; a rotation is not a per-second event. */
    private static final long JWKS_REFETCH_INTERVAL_MILLIS = 30_000;

    /**
     * What an ID token may say in its header {@code typ}: {@code JWT} or
     * nothing. An RFC 9068 access token says {@code at+jwt}, and is refused on
     * this path: it was issued to a resource, not to this client.
     */
    private static final JOSEObjectTypeVerifier<SecurityContext> ID_TOKEN_TYPES = DefaultJOSEObjectTypeVerifier.JWT;

    /**
     * What a token on the direct path may say: {@code at+jwt} or its media
     * type spelling (RFC 9068 §2.1 and §4), {@code JWT}, or nothing. The
     * audience rule in {@link #validateAccessToken(String)} is what keeps an
     * ID token off this path, so the type is informative here rather than
     * the gate.
     */
    private static final JOSEObjectTypeVerifier<SecurityContext> ACCESS_TOKEN_TYPES =
            new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT, new JOSEObjectType("at+jwt"),
                    new JOSEObjectType("application/at+jwt"), null);

    private final OidcConfig config;
    private final DiscoveryClient discovery;
    private String jwksUri;
    private JWKSource<SecurityContext> jwks;

    public OidcTokenValidator(OidcConfig config, DiscoveryClient discovery) {
        this.config = config;
        this.discovery = discovery;
    }

    /** The issuer this validator's discovery has seen, or null. Never fetches. */
    String cachedIssuer() {
        return discovery.cachedIssuer();
    }

    /** The discovery client this validator reads, for the sign-in flow's endpoints. */
    DiscoveryClient discovery() {
        return discovery;
    }

    /**
     * {@link #validate(String)} plus the nonce check that ties a token to the
     * sign-in attempt that asked for it. A token minted for some other attempt
     * — or obtained some other way — carries a different nonce or none.
     */
    public JWTClaimsSet validate(String token, String expectedNonce) throws Exception {
        JWTClaimsSet claims = validate(token);
        String nonce = claims.getStringClaim("nonce");
        if (expectedNonce == null || expectedNonce.isBlank() || !expectedNonce.equals(nonce)) {
            throw new BadJWTException("nonce rejected");
        }
        return claims;
    }

    /**
     * An ID token from this engine's own sign-in: {@link #verify(String)},
     * then audience and {@code azp} per OIDC Core 3.1.3.7.
     */
    public JWTClaimsSet validate(String token) throws Exception {
        JWTClaimsSet claims = verify(token, ID_TOKEN_TYPES);
        if (!claims.getAudience().contains(config.clientId())) {
            throw new BadJWTException("issuer or audience rejected");
        }
        // OIDC Core 3.1.3.7 items 4 and 5: several audiences require azp, and
        // an azp that is present must be this client.
        String azp = claims.getStringClaim("azp");
        if ((claims.getAudience().size() > 1 || azp != null) && !config.clientId().equals(azp)) {
            throw new BadJWTException("azp rejected");
        }
        return claims;
    }

    /**
     * A JWT access token presented as {@code oidc:jwt:}, validated the way a
     * resource server validates one (RFC 9068 §4): {@link #verify}, then
     * {@code aud} must name this engine ({@code jwt.audience}, never the client
     * id, so an ordinary ID token is not a password), {@code jti} must be
     * present so the token can be spent once, {@code exp - iat} must be at
     * most {@code jwt.max-lifetime-seconds} (a token for this engine is
     * obtained right before use), and when {@code jwt.allowed-clients} is set,
     * {@code client_id} must be one of them: only those clients may obtain a
     * token that signs in here.
     */
    public JWTClaimsSet validateAccessToken(String token) throws Exception {
        JWTClaimsSet claims = verify(token, ACCESS_TOKEN_TYPES);
        if (!claims.getAudience().contains(config.jwtAudience())) {
            throw new BadJWTException("audience rejected");
        }
        if (claims.getJWTID() == null || claims.getJWTID().isBlank()) {
            throw new BadJWTException("jti required");
        }
        long lifetime = claims.getExpirationTime().getTime() - claims.getIssueTime().getTime();
        if (lifetime > config.jwtMaxLifetimeSeconds() * 1000L) {
            throw new BadJWTException("token lifetime rejected");
        }
        if (!config.jwtAllowedClients().isEmpty()) {
            String clientId = claims.getStringClaim("client_id");
            if (clientId == null || !config.jwtAllowedClients().contains(clientId)) {
                throw new BadJWTException("client_id rejected");
            }
        }
        return claims;
    }

    /**
     * What every token must pass: an allowed asymmetric algorithm, a signature
     * from the provider's JWKS, a header {@code typ} the caller's path allows,
     * the discovered issuer, and an exp/iat/nbf window with skew. Audience is
     * the caller's rule.
     */
    private JWTClaimsSet verify(String token, JOSEObjectTypeVerifier<SecurityContext> allowedTypes) throws Exception {
        DiscoveryClient.Metadata metadata = discovery.get(config);
        SignedJWT parsed = SignedJWT.parse(token);
        String alg = parsed.getHeader().getAlgorithm().getName();
        if (!config.allowedAlgorithms().contains(alg) || alg.startsWith("HS") || "none".equalsIgnoreCase(alg)) {
            throw new BadJOSEException("algorithm not allowed");
        }

        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.parse(alg), jwksFor(metadata.jwksUri()));
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(keySelector);
        processor.setJWSTypeVerifier(allowedTypes);
        JWTClaimsSet claims = processor.process(parsed, null);

        if (!metadata.issuer().equals(claims.getIssuer())) {
            throw new BadJWTException("issuer or audience rejected");
        }
        if (claims.getExpirationTime() == null || claims.getIssueTime() == null) {
            throw new BadJWTException("token lifetime rejected");
        }
        long now = System.currentTimeMillis();
        long skewMillis = config.clockSkewSeconds() * 1000L;
        boolean notYetValid = claims.getNotBeforeTime() != null
                && claims.getNotBeforeTime().getTime() > now + skewMillis;
        boolean issuedInFuture = claims.getIssueTime().getTime() > now + skewMillis;
        if (now > acceptedUntilMillis(claims, config) || notYetValid || issuedInFuture) {
            throw new BadJWTException("token lifetime rejected");
        }
        return claims;
    }

    /**
     * The last instant {@link #validate(String)} accepts this token:
     * {@code min(exp, iat + maxAge) + skew}. The replay cache keeps a spent
     * token's record until then, so both windows come from this one place.
     * Requires {@code exp} and {@code iat}, which validation guarantees.
     */
    static long acceptedUntilMillis(JWTClaimsSet claims, OidcConfig config) {
        return Math.min(claims.getExpirationTime().getTime(),
                claims.getIssueTime().getTime() + config.maxTokenAgeSeconds() * 1000L)
                + config.clockSkewSeconds() * 1000L;
    }

    /** One cached remote JWKS per URI; rebuilt only if discovery moves it. */
    private synchronized JWKSource<SecurityContext> jwksFor(String uri) throws Exception {
        if (jwks == null || !uri.equals(jwksUri)) {
            long ttlMillis = Math.max(config.jwksCacheTtlSeconds(), 2) * 1000L;
            // An explicit retriever. Left to nimbus, the fetch ran on its
            // defaults — 500 ms to connect, 500 ms to read, a 50 KB body — which
            // an on-premises engine reaching a cloud provider misses routinely,
            // and the miss lands on whichever sign-in follows each cache expiry.
            // Every other fetch in this plugin is bounded deliberately; this one
            // was bounded by accident, and too tightly.
            ResourceRetriever retriever = new DefaultResourceRetriever(JWKS_TIMEOUT_MILLIS, JWKS_TIMEOUT_MILLIS, JWKS_MAX_BYTES);
            jwks = JWKSourceBuilder.<SecurityContext>create(new URL(uri), retriever)
                    .cache(ttlMillis, Math.min(ttlMillis / 2, JWKS_TIMEOUT_MILLIS))
                    .rateLimited(JWKS_REFETCH_INTERVAL_MILLIS)
                    .build();
            jwksUri = uri;
        }
        return jwks;
    }
}
