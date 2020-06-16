package com.pulsarix.micronaut.security.attributes.validation;


import com.pulsarix.micronaut.security.attributes.annotation.Attribute;
import com.pulsarix.micronaut.security.attributes.annotation.SecuredAttributes;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.SecurityRuleResult;
import java.util.Map;

/**
 * Authentication attributes validator.
 *
 * @see SecuredAttributes
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

