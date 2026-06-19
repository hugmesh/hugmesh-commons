package systems.snapdragon.commons.web;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for the canonical {@link ApiException}: the full union of HTTP-status
 * factory methods carries the right status + message.
 */
class ApiExceptionTest {

    @Test
    void factoriesCarryStatusAndMessage() {
        assertThat(ApiException.unauthorized("a").status()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiException.forbidden("b").status()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ApiException.notFound("c").status()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(ApiException.gone("d").status()).isEqualTo(HttpStatus.GONE);
        assertThat(ApiException.badRequest("e").status()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(ApiException.conflict("f").status()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(ApiException.badGateway("g").status()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(ApiException.serviceUnavailable("h").status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(ApiException.unprocessable("i").status()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(ApiException.forbidden("denied").getMessage()).isEqualTo("denied");
    }
}
