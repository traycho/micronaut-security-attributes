package com.pulsairx.micronaut.security.jwt.util;

import io.micronaut.security.token.Claims;

import java.util.ArrayList;
import java.util.List;

public class ClaimUtil {

    /**
     * Find a list of values for given claim using its name.
     *
     * @param claims    all claims
     * @param claimName a claim name
     * @return a list of values
     */
    public static List<String> findClaim(Claims claims, String claimName) {
        List<String> items = new ArrayList<>();
        Object rolesObject = claims.get(claimName);
        if (rolesObject != null) {
            if (rolesObject instanceof Iterable) {
                for (Object o : ((Iterable) rolesObject)) {
                    items.add(o.toString());
                }
            } else {
                items.add(rolesObject.toString());
            }
        }
        return items;
    }
}
