package com.pulsairx.micronaut.security.jwt.rules;

import com.pulsairx.micronaut.security.jwt.annotation.JwtClaim;
import com.pulsairx.micronaut.security.jwt.annotation.JwtClaims;
import com.pulsairx.micronaut.security.jwt.util.ClaimUtil;
import com.pulsairx.micronaut.security.jwt.validation.JwtClaimValidator;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.AbstractSecurityRule;
import io.micronaut.security.rules.SecuredAnnotationRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.MapClaims;
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
 * Jwt claims security rule.
 * It handles jwt claims annotation {@link JwtClaims}
 *
 * @see AbstractSecurityRule
 * @see JwtClaim
 * @see JwtClaims
 */
@Slf4j
@Singleton
public class JwtClaimsSecurityRule extends AbstractSecurityRule {

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
    JwtClaimsSecurityRule(final RolesFinder rolesFinder, final ApplicationContext applicationContext) {
        super(rolesFinder);
        this.applicationContext = applicationContext;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SecurityRuleResult check(final HttpRequest request, @Nullable final RouteMatch routeMatch, @Nullable Map<String, Object> claims) {
        SecurityRuleResult result = SecurityRuleResult.UNKNOWN;
        if (routeMatch instanceof MethodBasedRouteMatch) {
            MethodBasedRouteMatch methodRoute = ((MethodBasedRouteMatch) routeMatch);
            List<JwtClaim> jwtClaims = getJwtClaims(methodRoute);
            if (!jwtClaims.isEmpty()) {
                if (claims == null) {
                    claims = new HashMap<>();
                }
                Claims allClaims = new MapClaims(claims);
                for (JwtClaim jwtClaim : jwtClaims) {
                    if (jwtClaim.contains().length > 0) {
                        result = claimContains(jwtClaim, allClaims);
                    } else if (jwtClaim.matches().length() > 0) {
                        result = claimMatches(jwtClaim, allClaims);
                    } else {
                        result = claimValidator(request, jwtClaim, allClaims);
                    }

                    if (SecurityRuleResult.REJECTED.equals(result)) {
                        break;
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Jwt claims security rule result={}", result);
        }
        return result;
    }

    /**
     * Gets a list of {@link JwtClaim} annotations.
     *
     * @param methodRoute method route
     * @return a list of claim annotations
     */
    private List<JwtClaim> getJwtClaims(final MethodBasedRouteMatch methodRoute) {
        return methodRoute.getValue(JwtClaims.class, JwtClaim[].class)
                .map(Arrays::asList)
                .orElse(new ArrayList<>());
    }

    /**
     * Validates jwt claim using matches field.
     *
     * @param jwtClaim jwt claim
     * @param claims   all claims
     * @return {@link SecurityRuleResult}
     */
    private SecurityRuleResult claimMatches(JwtClaim jwtClaim, Claims claims) {
        if (log.isDebugEnabled()) {
            log.debug("Checks if claim={} matches={}", jwtClaim.name(), jwtClaim.matches());
        }
        SecurityRuleResult result = SecurityRuleResult.ALLOWED;
        List<String> actualValues = ClaimUtil.findClaim(claims, jwtClaim.name());

        Pattern pattern = compiledPattern(jwtClaim.matches());

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
     * Validates jwt claims using contains field.
     *
     * @param jwtClaim jwt claim
     * @param claims   all claims
     * @return {@link SecurityRuleResult}
     */
    private SecurityRuleResult claimContains(JwtClaim jwtClaim, Claims claims) {
        if (log.isDebugEnabled()) {
            log.debug("Checks if claim={} contains={}", jwtClaim.name(), jwtClaim.contains());
        }
        SecurityRuleResult result = SecurityRuleResult.ALLOWED;
        List<String> actualValues = ClaimUtil.findClaim(claims, jwtClaim.name());
        List<String> expectedValues = Arrays.asList(jwtClaim.contains());
        if (Collections.disjoint(actualValues, expectedValues)) {
            result = SecurityRuleResult.REJECTED;
        }
        return result;
    }

    /**
     * Validates a jwt claim using {@link JwtClaimValidator}.
     *
     * @param request  http request
     * @param jwtClaim jwt claim
     * @param claims   all claims
     * @return {@link SecurityRuleResult}
     */
    private SecurityRuleResult claimValidator(HttpRequest request, JwtClaim jwtClaim, Claims claims) {
        if (log.isDebugEnabled()) {
            log.debug("Checks claims validation using validator={}", jwtClaim.validator());
        }
        return applicationContext.getBean(jwtClaim.validator()).validate(request, claims);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getOrder() {
        return ORDER;
    }
}
