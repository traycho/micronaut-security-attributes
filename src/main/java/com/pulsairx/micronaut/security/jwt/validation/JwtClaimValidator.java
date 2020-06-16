package com.pulsairx.micronaut.security.jwt.validation;

import com.pulsairx.micronaut.security.jwt.annotation.JwtClaim;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.token.Claims;

/**
 * Jwt claim validator.
 *
 * @see Claims
 * @see JwtClaim
 */
public abstract class JwtClaimValidator {

    /**
     * Validates jwt claims.
     *
     * @param request http request
     * @param claims  jwt claims
     * @return {@link SecurityRuleResult}
     */
    public abstract SecurityRuleResult validate(HttpRequest request, Claims claims);
}

