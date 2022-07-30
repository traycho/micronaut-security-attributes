# micronaut-security-attributes

[![Maven Central](https://img.shields.io/maven-central/v/com.pulsarix.micronaut/micronaut-security-attributes.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22com.pulsarix.micronaut%22%20AND%20a:%22micronaut-security-attributes%22)
[![](https://github.com/traycho/micronaut-security-attributes/workflows/Java%20Build%20CI/badge.svg)](https://github.com/traycho/micronaut-security-attributes/actions)

Brings authentication attributes validation part of controller using annotations.
This is a tiny extension of `micronaut-security` using a new security rule `SecuredAttributesRule` handling `@SecuredAttributes` annotation.
Library is not related to any particular authentication method its target is to handle in generic way authentication attributes available in 
`Authentication` instance. 

For more details check https://micronaut-projects.github.io/micronaut-security/latest/api/io/micronaut/security/authentication/Authentication.html


## Setup

To use the Micronaut’s security capabilities you must have the security dependency on your classpath. For example in `build.gradle`

Official Micronaut Security Guide` is available with following link https://micronaut-projects.github.io/micronaut-security/latest/guide/

```groovy
dependencies{ 
    annotationProcessor "io.micronaut:micronaut-security"
    compile "io.micronaut:micronaut-security"

    // Set your preferred authentication method 
    // compile "io.micronaut.configuration:micronaut-security-ldap"
    // compile "io.micronaut.configuration:micronaut-security-jwt"  

    compile "com.pulsarix.micronaut:micronaut-security-attributes:1.0.0"
}
```

## Examples

### Validate authentication attribute using `contains` parameter
```java
@Controller
class Controller{
        @Get
        @SecuredAttributes(value={
           @Attribute(name="iss", contains={ "appIssuer"}),
        })
        public HttpResponse index(){
            // your endpoint code here
        }       
}
```

### Validate authentication attribute using `matches` parameter
```java
@Controller
class Controller{
        @Get
        @SecuredAttributes(value={
           @Attribute(name="iss", matches="[a-zA-z]+"),
        })
        public HttpResponse index(){
            // your endpoint code here
        }       
}
```
  
### Validate multiple authentication attributes using `contains` parameter
```java
@Controller
class Controller{
        @Get
        @SecuredAttributes(value={
                @Attribute(name="iss", contains={ "appIssuer" }),
                @Attribute(name="scp", contains={"read"})
        })
        public HttpResponse index(){
            // your endpoint code here
        }       
}
```

### Validate authentication attribute using custom `validator`
As first step create a new validator class by implementing `SecuredAttributeValidator`.
Given example below is validating if resouce identifier is part of `scopes` claim of jwt token. 
```java
@Singleton
public class ResourceIdScopeValidator extends SecuredAttributeValidator {

    private static final String ATTRIBUTE_SCOPES = "scp";

    /**
     * {@inheritDoc}
     */
    @Override
    public SecurityRuleResult validate(HttpRequest request, Map<String, Object> attributes) {

        SecurityRuleResult result = SecurityRuleResult.REJECTED;

        if (attributes != null) {
            List<String> scopes = Attributes.find(attributes, ATTRIBUTE_SCOPES);
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
```

```java
@Controller
class Controller{
        @Get("/resource/{id}")
        @SecuredAttributes(value={
             @Attribute(validator=ResourceIdScopeValidator.class) 
        })
        public HttpResponse index(final @PathVariable String id){
            // your endpoint code here
        }       
}
```

