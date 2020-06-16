package com.pulsarix.micronaut.security.attributes.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Attributes {

    /**
     * Find a list of values for given attribute using its name.
     *
     * @param attributes    a map of attributes
     * @param attributeName an attribute name
     * @return a list of values
     */
    public static List<String> find(Map<String, Object> attributes, String attributeName) {
        List<String> items = new ArrayList<>();
        Object attribute = attributes.get(attributeName);
        if (attribute != null) {
            if (attribute instanceof Iterable) {
                for (Object obj : ((Iterable) attribute)) {
                    items.add(obj.toString());
                }
            } else {
                items.add(attribute.toString());
            }
        }
        return items;
    }
}
