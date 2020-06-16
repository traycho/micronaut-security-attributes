# micronaut-security-jwt

Brings claims validation of jwt tokens as part of controller using annotations.
This is a tiny extension of `micronaut-security` using a new security rule `JwtClaimsSecurityRule` handling `@JwtClaims` annotation.


### Validate claim using `contains parameter
```java
@Controller
class Controller{
        @JwtClaims(value={
           @JwtClaim(name="iss", contains={ "appIssuer"}),
        })
        @Get
        public HttpResponse index(){
            // your endpoint code here
        }       
}
```

### Validate claim using `matches` parameter
```java
@Controller
class Controller{
        @JwtClaims(value={
           @JwtClaim(name="iss", matches="[a-zA-z]+"),
        })
        @Get
        public HttpResponse index(){
            // your endpoint code here
        }       
}
```
  
### Validate multiple claims
```java
@Controller
class Controller{
        @JwtClaims(value={
                @JwtClaim(name="iss", contains={ "appIssuer" }),
                @JwtClaim(name="scp", contains={"read"})
        })
        @Get
        public HttpResponse index(){
            // your endpoint code here
        }       
}
```

### Validate claims using custom `validator`
```java
@Controller
class Controller{
        @JwtClaims(value={
             @JwtClaim(validator=ResourceIdScopeValidator.class) 
        })
        @Get("/resource/{id}")
        public HttpResponse index(final @PathVariable String id){
            // your endpoint code here
        }       
}
```
