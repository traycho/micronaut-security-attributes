package example.jwt;

import io.micronaut.runtime.Micronaut;

public class Application {

    public static final String NAME = "example-jwt";

    public static void main(String[] args) {
        Micronaut.run(Application.class);
    }
}
