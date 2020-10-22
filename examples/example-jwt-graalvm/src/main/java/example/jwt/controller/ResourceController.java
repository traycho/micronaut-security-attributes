package example.jwt.controller;

import com.pulsarix.micronaut.security.attributes.annotation.Attribute;
import com.pulsarix.micronaut.security.attributes.annotation.SecuredAttributes;
import example.jwt.Application;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecuredAnnotationRule;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;


@Controller
@Secured(SecuredAnnotationRule.IS_AUTHENTICATED)
public class ResourceController {

    @Get
    @SecuredAttributes(value = {
            @Attribute(name = JwtClaims.ISSUER, contains = {Application.NAME}),
            @Attribute(name = JwtClaims.SUBJECT, contains = {"user"})
    })
    public HttpResponse index() {
        return HttpResponse.ok();
    }
}
