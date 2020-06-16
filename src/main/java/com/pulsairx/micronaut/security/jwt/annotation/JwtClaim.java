package com.pulsairx.micronaut.security.jwt.annotation;

import com.pulsairx.micronaut.security.jwt.validation.JwtClaimValidator;

public @interface JwtClaim {

    String name() default "";

    String[] contains() default {};

    String matches() default "";

    Class<? extends JwtClaimValidator> validator() default JwtClaimValidator.class;
}
