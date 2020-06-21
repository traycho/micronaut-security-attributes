package com.pulsarix.micronaut.security.attributes.rules;

import com.pulsarix.micronaut.security.attributes.annotation.Attribute;
import com.pulsarix.micronaut.security.attributes.annotation.SecuredAttributes;
import com.pulsarix.micronaut.security.attributes.util.Attributes;
import com.pulsarix.micronaut.security.attributes.validation.SecuredAttributeValidator;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.AbstractSecurityRule;
import io.micronaut.security.rules.SecuredAnnotationRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authentication attributes security rule.
 * It handles authentication attributes annotation {@link SecuredAttributes}
 *
 * @see AbstractSecurityRule
 * @see Attribute
 * @see SecuredAttributes
 */
@Singleton
public class SecuredAttributesRule extends AbstractSecurityRule {

    /**
     * Default logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SecuredAttributesRule.class);

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = SecuredAnnotationRule.ORDER - 100;

    /**
     * Application context.
     */
    private final ApplicationContext applicationContext;

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
            List<Attribute> attributesAnnotations = getAttributes(methodRoute);
            if (!attributesAnnotations.isEmpty()) {
                if (attributes == null) {
                    attributes = new HashMap<>();
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Checking secured attributes={}", attributes);
                }
                for (Attribute attribute : attributesAnnotations) {
                    if (attribute.contains().length > 0) {
                        result = attributeContains(attribute, attributes);
                    } else if (attribute.matches().length() > 0) {
                        result = attributeMatches(attribute, attributes);
                    } else {
                        result = attributeValidator(request, attribute, attributes);
                    }

                    if (SecurityRuleResult.REJECTED.equals(result)) {
                        break;
                    }
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Security attributes rule result is {}", result);
        }
        return result;
    }

    /**
     * Gets a list of {@link Attribute} annotations.
     *
     * @param methodRoute method route
     * @return a list of attributes annotations
     */
    private List<Attribute> getAttributes(final MethodBasedRouteMatch methodRoute) {
        return methodRoute.getValue(SecuredAttributes.class, Attribute[].class)
                .map(Arrays::asList)
                .orElse(new ArrayList<>());
    }

    /**
     * Validates authentication attribute using matches field.
     *
     * @param attribute  authentication attribute
     * @param attributes all authentication attributes
     * @return {@link SecurityRuleResult}
     */
    private SecurityRuleResult attributeMatches(Attribute attribute, Map<String, Object> attributes) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Checks if attribute={} matches={}", attribute.name(), attribute.matches());
        }
        SecurityRuleResult result = SecurityRuleResult.REJECTED;

        if (Attributes.matches(attribute.name(), attribute.matches(), attributes)) {
            result = SecurityRuleResult.ALLOWED;
        }
        return result;
    }

    /**
     * Validates authentication attributes using contains field.
     *
     * @param attribute  authentication attribute
     * @param attributes all authentication attributes
     * @return {@link SecurityRuleResult}
     */
    private SecurityRuleResult attributeContains(Attribute attribute, Map<String, Object> attributes) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Checks if attribute={} contains={}", attribute.name(), attribute.contains());
        }

        SecurityRuleResult result = SecurityRuleResult.REJECTED;
        if (Attributes.contains(attribute.name(), Arrays.asList(attribute.contains()), attributes)) {
            result = SecurityRuleResult.ALLOWED;
        }
        return result;
    }

    /**
     * Validates a authentication attribute using {@link SecuredAttributeValidator}.
     *
     * @param request    http request
     * @param attribute  authentication attribute
     * @param attributes all authentication attributes
     * @return {@link SecurityRuleResult}
     */
    private SecurityRuleResult attributeValidator(HttpRequest request, Attribute attribute, Map<String, Object> attributes) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Checks attribute validation using validator={}", attribute.validator());
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
