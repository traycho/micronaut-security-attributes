# micronaut-security-attributes

[![](https://github.com/traycho/micronaut-security-attributes/workflows/Java%20Build%20CI/badge.svg)](https://github.com/traycho/micronaut-security-attributes/actions)

Brings authentication attributes validation part of controller using annotations.
This is a tiny extension of `micronaut-security` using a new security rule `SecuredAttributesRule` handling `@SecuredAttributes` annotation.
Library is not related to any particular authentication method its target is to handle in generic way authentication attributes available in 
`Authentication` instance. 

For more details check https://docs.micronaut.io/latest/api/io/micronaut/security/authentication/Authentication.html

## Setup

To use the Micronaut’s security capabilities you must have the security dependency on your classpath. For example in `build.gradle`

```groovy
dependencies{ 
    annotationProcessor "io.micronaut:micronaut-security"
    compile "io.micronaut:micronaut-security"
    
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
