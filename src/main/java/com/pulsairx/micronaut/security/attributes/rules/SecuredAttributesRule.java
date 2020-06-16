package com.pulsairx.micronaut.security.attributes.rules;

import com.pulsairx.micronaut.security.attributes.annotation.Attribute;
import com.pulsairx.micronaut.security.attributes.annotation.SecuredAttributes;
import com.pulsairx.micronaut.security.attributes.util.AttributesUtil;
import com.pulsairx.micronaut.security.attributes.validation.SecuredAttributeValidator;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.AbstractSecurityRule;
import io.micronaut.security.rules.SecuredAnnotationRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import lombok.extern.slf4j.Slf4j;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Authentication attributes security rule.
 * It handles authentication attributes annotation {@link SecuredAttributes}
 *
 * @see AbstractSecurityRule
 * @see Attribute
 * @see SecuredAttributes
 */
@Slf4j
@Singleton
public class SecuredAttributesRule extends AbstractSecurityRule {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = SecuredAnnotationRule.ORDER - 100;

    /**
     * Compiled patterns.
     */
    private static final Map<String, Pattern> COMIPLED_PATTERNS = new ConcurrentHashMap<>();

    /**
     * Application context.
     */
    private ApplicationContext applicationContext;

    /**
     * Constructor.
     *
     * @param rolesFinder        roles finder
     * @param applicationContext application context
     */
    @Inject
    SecuredAttributesRule(final RolesFinder rolesFinder, final ApplicationContext applicationContext) {
        super(rolesFinder);
        this.applicationContext = applicationContext;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SecurityRuleResult check(final HttpRequest request, @Nullable final RouteMatch routeMatch, @Nullable Map<String, Object> attributes) {
        SecurityRuleResult result = SecurityRuleResult.UNKNOWN;
        if (routeMatch instanceof MethodBasedRouteMatch) {
            MethodBasedRouteMatch methodRoute = ((MethodBasedRouteMatch) routeMatch);
            List<Attribute> attributesAnnotaions = getAttributes(methodRoute);
            if (!attributesAnnotaions.isEmpty()) {
                if (attributes == null) {
                    attributes = new HashMap<>();
                }
                for (Attribute attribute : attributesAnnotaions) {
                    if (attribute.contains().length > 0) {
                        result = claimContains(attribute, attributes);
                    } else if (attribute.matches().length() > 0) {
                        result = claimMatches(attribute, attributes);
                    } else {
                        result = claimValidator(request, attribute, attributes);
                    }

                    if (SecurityRuleResult.REJECTED.equals(result)) {
                        break;
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Attributes security rule result={}", result);
        }
        return result;
    }

    /**
     * Gets a list of {@link Attribute} annotations.
     *
     * @param methodRoute method route
     * @return a list of claim annotations
     */
    private List<Attribute> getAttributes(final MethodBasedRouteMatch methodRoute) {
        return methodRoute.getValue(SecuredAttributes.class, Attribute[].class)
                .map(Arrays::asList)
                .orElse(new ArrayList<>());
    }

    /**
     * Validates authentication attribute using matches field.
     *
     * @param attribute authentication attribute
     * @param attributes all authentication attributes
     * @return {@link SecurityRuleResult}
     */
    private SecurityRuleResult claimMatches(Attribute attribute, Map<String,Object> attributes) {
        if (log.isDebugEnabled()) {
            log.debug("Checks if attribute={} matches={}", attribute.name(), attribute.matches());
        }
        SecurityRuleResult result = SecurityRuleResult.ALLOWED;
        List<String> actualValues = AttributesUtil.findClaim(attributes, attribute.name());

        Pattern pattern = compiledPattern(attribute.matches());

        boolean found = false;
        for (String value : actualValues) {
            Matcher matcher = pattern.matcher(value);
            if (matcher.matches()) {
                found = true;
                break;
            }
        }

        if (!found) {
            result = SecurityRuleResult.REJECTED;
        }
        return result;
    }

    /**
     * Reuse existing pattern and compile only in case it is not available.
     *
     * @param regex regex pattern
     * @return {@link Pattern}
     */
    private Pattern compiledPattern(String regex) {
        Pattern pattern = COMIPLED_PATTERNS.get(regex);
        if (pattern == null) {
            pattern = Pattern.compile(regex);
            COMIPLED_PATTERNS.put(regex, pattern);
        }
        return pattern;
    }

    /**
     * Validates authentication attributes using contains field.
     *
     * @param attribute authentication attribute
     * @param attributes all authentication attrobutes
     * @return {@link SecurityRuleResult}
     */
    private SecurityRuleResult claimContains(Attribute attribute, Map<String,Object> attributes) {
        if (log.isDebugEnabled()) {
            log.debug("Checks if attribute={} contains={}", attribute.name(), attribute.contains());
        }
        SecurityRuleResult result = SecurityRuleResult.ALLOWED;
        List<String> actualValues = AttributesUtil.findClaim(attributes, attribute.name());
        List<String> expectedValues = Arrays.asList(attribute.contains());
        if (Collections.disjoint(actualValues, expectedValues)) {
            result = SecurityRuleResult.REJECTED;
        }
        return result;
    }

    /**
     * Validates a authnetication attribute using {@link SecuredAttributeValidator}.
     *
     * @param request  http request
     * @param attribute authentication attribute
     * @param attributes all authentication attributes
     * @return {@link SecurityRuleResult}
     */
    private SecurityRuleResult claimValidator(HttpRequest request, Attribute attribute, Map<String,Object> attributes) {
        if (log.isDebugEnabled()) {
            log.debug("Checks attribute validation using validator={}", attribute.validator());
        }
        return applicationContext.getBean(attribute.validator()).validate(request, attributes);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getOrder() {
        return ORDER;
    }
}
