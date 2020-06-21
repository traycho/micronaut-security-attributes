package example.jwt.controller;

import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.jwt.generator.claims.ClaimsGenerator;
import io.micronaut.test.annotation.MicronautTest;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@MicronautTest
public class ResourceControllerTest {

    private static final Logger LOG = LoggerFactory.getLogger(ResourceControllerTest.class);

    @Inject
    @Client("/")
    RxHttpClient client;

    @Inject
    ClaimsGenerator claimsGenerator;

    @Inject
    TokenGenerator tokenGenerator;

    @Test
    public void testGetWithoutToken() {

        HttpClientResponseException thrown = assertThrows(HttpClientResponseException.class, () -> {
            client.toBlocking().exchange(HttpRequest.GET("/"));
        });
        assertEquals(HttpStatus.UNAUTHORIZED, thrown.getResponse().getStatus());
    }

    @Test
    public void testGet() {
        UserDetails user = new UserDetails("user", Collections.emptyList());
        String token = tokenGenerator.generateToken(user, 30).
                orElseThrow(() -> new IllegalStateException("no token provided"));

        LOG.info("Generated token: {}", token);
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.GET("/").
                header(HttpHeaders.AUTHORIZATION, "Bearer " + token), String.class);

        assertEquals(HttpStatus.OK, response.getStatus());
    }

    @Test
    public void testGetWithWrongAttibutes() {
        UserDetails user = new UserDetails("unknown-user", Collections.emptyList());
        String token = tokenGenerator.generateToken(user, 30).
                orElseThrow(() -> new IllegalStateException("no token provided"));

        HttpClientResponseException thrown = assertThrows(HttpClientResponseException.class, () -> {
            client.toBlocking().exchange(HttpRequest.GET("/").
                    header(HttpHeaders.AUTHORIZATION, "Bearer " + token), String.class);
        });
        assertEquals(HttpStatus.FORBIDDEN, thrown.getResponse().getStatus());
    }
}
