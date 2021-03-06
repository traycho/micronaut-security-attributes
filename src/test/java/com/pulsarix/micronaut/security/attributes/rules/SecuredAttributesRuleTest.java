package com.pulsarix.micronaut.security.attributes.rules;


import com.pulsarix.micronaut.security.attributes.annotation.Attribute;
import com.pulsarix.micronaut.security.attributes.annotation.SecuredAttributes;
import com.pulsarix.micronaut.security.attributes.validation.SecuredAttributeValidator;
import com.pulsarix.micronaut.security.attributes.validation.ResourceIdScopeValidator;
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
public class SecuredAttributesRuleTest {

    private static final String ATTRIBUTE_SCOPES = "scp";

    private static final String ATTRIBUTE_ISSUER = "iss";

    @Mock
    private RolesFinder rolesFinder;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private MethodBasedRouteMatch routeMatch;

    @Mock
    private HttpRequest httpRequest;

    private SecuredAttributesRule securityRule;

    @BeforeEach
    public void setUp() {
        this.securityRule = new SecuredAttributesRule(rolesFinder, applicationContext);
    }

    void setupExpectedAttributes(Attribute[] attributes) {
        Optional expectedAttributes = Optional.of(attributes);
        Mockito.when(routeMatch.getValue(SecuredAttributes.class, Attribute[].class)).thenReturn(expectedAttributes);
    }

    Attribute createAttributeAnnotation(String name, String[] contains, String matches, Class<? extends SecuredAttributeValidator> attributeValidator) {
        return new Attribute() {

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
            public Class<? extends SecuredAttributeValidator> validator() {
                return attributeValidator;
            }
        };
    }

    @Test
    void testSecuredAttributeWithNullableParams() {
        SecurityRuleResult result = this.securityRule.check(httpRequest, null, null);
        Assertions.assertEquals(SecurityRuleResult.UNKNOWN, result);
    }

    @Test
    void testContainsParameter() {
        String issuer = "issuer";
        setupExpectedAttributes(new Attribute[]{
                createAttributeAnnotation(ATTRIBUTE_ISSUER, new String[]{issuer}, null, null)
        });
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_ISSUER, issuer);
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, attributes);
        Assertions.assertEquals(SecurityRuleResult.ALLOWED, result);
    }

    @Test
    void testContainsParameterWithRejection() {
        String issuer = "issuer";
        String notExpctedIssuer = "notExpectedIssuer";
        setupExpectedAttributes(new Attribute[]{
                createAttributeAnnotation(ATTRIBUTE_ISSUER, new String[]{issuer}, null, null)
        });

        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_ISSUER, notExpctedIssuer);
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, attributes);
        Assertions.assertEquals(SecurityRuleResult.REJECTED, result);
    }

    @Test
    void testValidatorParameter() throws URISyntaxException {
        String resourceId = UUID.randomUUID().toString();
        setupExpectedAttributes(new Attribute[]{
                createAttributeAnnotation(null, null, null, ResourceIdScopeValidator.class)
        });
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SCOPES, resourceId);
        Mockito.when(httpRequest.getUri()).thenReturn(new URI("/resource/" + resourceId));
        Mockito.when(applicationContext.getBean(ResourceIdScopeValidator.class)).thenReturn(new ResourceIdScopeValidator());
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, attributes);
        Assertions.assertEquals(SecurityRuleResult.ALLOWED, result);
    }

    @Test
    void testValidatorParameterRejected() throws URISyntaxException {
        String resourceId = UUID.randomUUID().toString();
        String unexpectedResourceId = UUID.randomUUID().toString();
        setupExpectedAttributes(new Attribute[]{
                createAttributeAnnotation(null, null, null, ResourceIdScopeValidator.class)
        });
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SCOPES, unexpectedResourceId);
        Mockito.when(httpRequest.getUri()).thenReturn(new URI("/resource/" + resourceId));
        Mockito.when(applicationContext.getBean(ResourceIdScopeValidator.class)).thenReturn(new ResourceIdScopeValidator());
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, attributes);
        Assertions.assertEquals(SecurityRuleResult.REJECTED, result);
    }

    @Test
    void testMatchesParameter() throws URISyntaxException {
        String issuer = "onlyLetters";
        setupExpectedAttributes(new Attribute[]{
                createAttributeAnnotation(ATTRIBUTE_ISSUER, null, "[a-zA-z]+", null)
        });
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_ISSUER, issuer);
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, attributes);
        Assertions.assertEquals(SecurityRuleResult.ALLOWED, result);
    }

    @Test
    void testMatchesParameterRejected() throws URISyntaxException {
        String issuer = "1234567890";
        setupExpectedAttributes(new Attribute[]{
                createAttributeAnnotation("iss", null, "[a-zA-z]+", null)
        });
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_ISSUER, issuer);
        SecurityRuleResult result = this.securityRule.check(httpRequest, routeMatch, attributes);
        Assertions.assertEquals(SecurityRuleResult.REJECTED, result);
    }
}
