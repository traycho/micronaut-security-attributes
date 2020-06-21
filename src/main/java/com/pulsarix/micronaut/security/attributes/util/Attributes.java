package com.pulsarix.micronaut.security.attributes.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Secured attributes utility class.
 */
public class Attributes {

    /**
     * Compiled patterns.
     */
    private static final Map<String, Pattern> COMPILED_PATTERNS = new ConcurrentHashMap<>();

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

    /**
     * Checks if a given attribute name and regular expression matches.
     *
     * @param name       attribute name
     * @param regex      regular expression
     * @param attributes all attributes
     * @return true if attribute matches otherwise false.
     */
    public static boolean matches(String name, String regex, Map<String, Object> attributes) {
        List<String> actualValues = find(attributes, name);
        Pattern pattern = compiledPattern(regex);
        return actualValues.stream().anyMatch((value) -> pattern.matcher(value).matches());
    }

    /**
     * Checks if a given attribute name and any of the expected value is available.
     *
     * @param name           attribute name
     * @param expectedValues a list of expected values to contain in attribute values.
     * @param attributes     all attributes
     * @return true if attribute values contain otherwise false.
     */
    public static boolean contains(String name, List<String> expectedValues, Map<String, Object> attributes) {
        boolean contains = false;
        List<String> actualValues = find(attributes, name);
        if (!Collections.disjoint(actualValues, expectedValues)) {
            contains = true;
        }
        return contains;

    }

    /**
     * Reuse existing pattern and compile only in case it is not available.
     *
     * @param regex regex pattern
     * @return {@link Pattern}
     */
    private static Pattern compiledPattern(String regex) {
        return COMPILED_PATTERNS.computeIfAbsent(regex, (key) -> Pattern.compile(key));
    }
}
