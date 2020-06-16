package com.pulsairx.micronaut.security.jwt.rules;


import com.pulsairx.micronaut.security.jwt.annotation.JwtClaim;
import com.pulsairx.micronaut.security.jwt.annotation.JwtClaims;
import com.pulsairx.micronaut.security.jwt.validation.JwtClaimValidator;
import com.pulsairx.micronaut.security.jwt.validation.ResourceIdScopeValidator;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.web.router.MethodBasedRouteMatch;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.annotation.Annotation;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
public class JwtClaimsSecurityRuleTest {

    private static final String SCOPES = "scp";

    private static final String ISSUER = "iss";

    @Mock
    private RolesFinder rolesFinder;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private MethodBasedRouteMatch routeMatch;

    @Mock
    private HttpRequest httpRequest;

    private JwtClaimsSecurityRule securityRule;

    @BeforeEach
    public void setUp() {
        this.securityRule = new JwtClaimsSecurityRule(rolesFinder, applicationContext);
    }

    void setupExpectedClaims(JwtClaim[] claims) {
        Optional expectedClaims = Optional.of(claims);
        Mockito.when(routeMatch.getValue(JwtClaims.class, JwtClaim[].class)).thenReturn(expectedClaims);
    }

    JwtClaim createClaimAnnotation(String name, String[] contains, String matches, Class<? extends JwtClaimValidator> jwtClaimValidator) {
        return new JwtClaim() {

            @Override
            public Class<? extends Annotation> annotationType() {
                return null;
            }

            @Override
            public String name() {
                return name != null ? name : "";
            }

            @Override
            public String[] contains() {
                return contains != null ? contains : new String[0];
            }

            @Override
            public String matches() {
                return matches != null ? matches : "";
            }

            @Override
            public Class<? extends JwtClaimValidator> validator() {
                return jwtClaimValidator;
            }
        };
    }

    @Test
    void testJwtClaimsWithNullableParams() {
        SecurityRuleResult result = this.securityRule.check(httpRequest, null, null);
        Assertions.assertEquals(SecurityRuleResult.UNKNOWN, result);
    }

    @Test
    void testContainsParameter() {
        String issuer = "issuer";
        setupExpectedClaims(new JwtClaim[]{
                createClaimAnnotation(io.micronaut.security.token.jwt.generator.claims.JwtClaims.ISSUER, new String[]{issuer}, null, null)
        });
        Map<String, Object> claims = new HashMap<>();
        claims.put(ISSUER, issuer);
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, claims);
        Assertions.assertEquals(SecurityRuleResult.ALLOWED, result);
    }

    @Test
    void testContainsParameterWithRejection() {
        String issuer = "issuer";
        String notExpctedIssuer = "notExpectedIssuer";
        setupExpectedClaims(new JwtClaim[]{
                createClaimAnnotation(ISSUER, new String[]{issuer}, null, null)
        });

        Map<String, Object> claims = new HashMap<>();
        claims.put(ISSUER, notExpctedIssuer);
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, claims);
        Assertions.assertEquals(SecurityRuleResult.REJECTED, result);
    }

    @Test
    void testValidatorParameter() throws URISyntaxException {
        String resourceId = UUID.randomUUID().toString();
        setupExpectedClaims(new JwtClaim[]{
                createClaimAnnotation(null, null, null, ResourceIdScopeValidator.class)
        });
        Map<String, Object> claims = new HashMap<>();
        claims.put(SCOPES, resourceId);
        Mockito.when(httpRequest.getUri()).thenReturn(new URI("/resource/" + resourceId));
        Mockito.when(applicationContext.getBean(ResourceIdScopeValidator.class)).thenReturn(new ResourceIdScopeValidator());
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, claims);
        Assertions.assertEquals(SecurityRuleResult.ALLOWED, result);
    }

    @Test
    void testValidatorParameterRejected() throws URISyntaxException {
        String resourceId = UUID.randomUUID().toString();
        String unexpectedResourceId = UUID.randomUUID().toString();
        setupExpectedClaims(new JwtClaim[]{
                createClaimAnnotation(null, null, null, ResourceIdScopeValidator.class)
        });
        Map<String, Object> claims = new HashMap<>();
        claims.put(SCOPES, unexpectedResourceId);
        Mockito.when(httpRequest.getUri()).thenReturn(new URI("/resource/" + resourceId));
        Mockito.when(applicationContext.getBean(ResourceIdScopeValidator.class)).thenReturn(new ResourceIdScopeValidator());
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, claims);
        Assertions.assertEquals(SecurityRuleResult.REJECTED, result);
    }

    @Test
    void testMatchesParameter() throws URISyntaxException {
        String issuer = "onlyLetters";
        setupExpectedClaims(new JwtClaim[]{
                createClaimAnnotation(ISSUER, null, "[a-zA-z]+", null)
        });
        Map<String, Object> claims = new HashMap<>();
        claims.put(ISSUER, issuer);
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, claims);
        Assertions.assertEquals(SecurityRuleResult.ALLOWED, result);
    }

    @Test
    void testMatchesParameterRejected() throws URISyntaxException {
        String issuer = "1234567890";
        setupExpectedClaims(new JwtClaim[]{
                createClaimAnnotation("iss", null, "[a-zA-z]+", null)
        });
        Map<String, Object> claims = new HashMap<>();
        claims.put(ISSUER, issuer);
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, claims);
        Assertions.assertEquals(SecurityRuleResult.REJECTED, result);
    }
}
