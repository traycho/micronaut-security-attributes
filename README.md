# pulsarix-micronaut-security

Brings authentication attributes validationas part of controller using annotations.
This is a tiny extension of `micronaut-security` using a new security rule `SecuredAttributesRule` handling `@SecuredAttributes` annotation.


### Validate authentication attribute using `contains parameter
```java
@Controller
class Controller{
        @SecuredAttributes(value={
           @Attribute(name="iss", contains={ "appIssuer"}),
        })
        @Get
        public HttpResponse index(){
            // your endpoint code here
        }       
}
```

### Validate authentication attribute using `matches` parameter
```java
@Controller
class Controller{
        @SecuredAttributes(value={
           @Attribute(name="iss", matches="[a-zA-z]+"),
        })
        @Get
        public HttpResponse index(){
            // your endpoint code here
        }       
}
```
  
### Validate multiple authentication attributes
```java
@Controller
class Controller{
        @SecuredAttributes(value={
                @Attribute(name="iss", contains={ "appIssuer" }),
                @Attribute(name="scp", contains={"read"})
        })
        @Get
        public HttpResponse index(){
            // your endpoint code here
        }       
}
```

### Validate authentication attribute using custom `validator
```java
@Controller
class Controller{
        @SecuredAttributes(value={
             @Attribute(validator=ResourceIdScopeValidator.class) 
        })
        @Get("/resource/{id}")
        public HttpResponse index(final @PathVariable String id){
            // your endpoint code here
        }       
}
```
