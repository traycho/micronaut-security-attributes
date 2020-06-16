package com.pulsarix.micronaut.security.attributes.annotation;

import com.pulsarix.micronaut.security.attributes.validation.SecuredAttributeValidator;

public @interface Attribute {

    String name() default "";

    String[] contains() default {};

    String matches() default "";

    Class<? extends SecuredAttributeValidator> validator() default SecuredAttributeValidator.class;
}
