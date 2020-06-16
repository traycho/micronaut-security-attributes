package com.pulsairx.micronaut.security.attributes.validation;


import com.pulsairx.micronaut.security.attributes.util.AttributesUtil;
import io.micronaut.context.annotation.Prototype;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.SecurityRuleResult;

import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * Validates if resource id is part of authentication scope attributes.
 */
@Prototype
public class ResourceIdScopeValidator extends SecuredAttributeValidator {

    /**
     * {@inheritDoc}
     */
    @Override
    public SecurityRuleResult validate(HttpRequest request, Map<String,Object> attributes) {
        SecurityRuleResult result = SecurityRuleResult.REJECTED;

        if (attributes != null) {
            List<String> scopes = AttributesUtil.findClaim(attributes, "scp");
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
