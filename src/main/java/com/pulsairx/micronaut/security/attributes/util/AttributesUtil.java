package com.pulsairx.micronaut.security.attributes.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AttributesUtil {

    /**
     * Find a list of values for given claim using its name.
     *
     * @param claims    all claims
     * @param claimName a claim name
     * @return a list of values
     */
    public static List<String> findClaim(Map<String,Object> claims, String claimName) {
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
