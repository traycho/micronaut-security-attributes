package com.pulsairx.micronaut.security.attributes.validation;

import com.pulsairx.micronaut.security.attributes.annotation.Attribute;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.token.Claims;

import java.util.Map;

/**
 * Authentication attributes validator.
 *
 * @see Claims
 * @see Attribute
 */
public abstract class SecuredAttributeValidator {

    /**
     * Validates authentication attributes.
     *
     * @param request http request
     * @param attributes authentication attributes
     * @return {@link SecurityRuleResult}
     */
    public abstract SecurityRuleResult validate(HttpRequest request, Map<String,Object> attributes);
}

