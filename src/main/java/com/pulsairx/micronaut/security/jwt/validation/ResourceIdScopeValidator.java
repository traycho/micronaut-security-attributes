package com.pulsairx.micronaut.security.jwt.validation;


import com.pulsairx.micronaut.security.jwt.util.ClaimUtil;
import io.micronaut.context.annotation.Prototype;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.token.Claims;

import java.net.URI;
import java.util.List;

/**
 * Validates if resource id is part of jwt token scopes.
 */
@Prototype
public class ResourceIdScopeValidator extends JwtClaimValidator {

    /**
     * {@inheritDoc}
     */
    @Override
    public SecurityRuleResult validate(HttpRequest request, Claims claims) {
        SecurityRuleResult result = SecurityRuleResult.REJECTED;

        if (claims != null) {
            List<String> scopes = ClaimUtil.findClaim(claims, "scp");
            String resourceId = getResourceId(request);
            if (scopes.contains(resourceId)) {
                result = SecurityRuleResult.ALLOWED;
            }
        }

        return result;
    }

    /**
     * Gets resource id from given http request.
     *
     * @param request http request
     * @return resource identifier
     */
    String getResourceId(HttpRequest request) {
        URI uri = request.getUri();
        String path = uri.getPath();
        return path.substring(path.lastIndexOf('/') + 1);
    }
}
