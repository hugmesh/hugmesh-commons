package systems.snapdragon.commons.web;

import org.springframework.http.HttpStatus;

/**
 * Carries an HTTP status + a message rendered as the {@code {"error": msg}} JSON
 * body the BFF UIs expect. Thrown by the BFF controllers for the application-level
 * (session) checks; handled by each repo's reactive exception handler.
 *
 * <p>Canonical, shared form (the per-repo copies differed only in WHICH factory
 * methods they declared — this carries the UNION of all of them). Lifted
 * {@code public} for cross-repo use.
 */
public class ApiException extends RuntimeException {

    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus status() { return status; }

    public static ApiException unauthorized(String msg)       { return new ApiException(HttpStatus.UNAUTHORIZED, msg); }
    public static ApiException forbidden(String msg)          { return new ApiException(HttpStatus.FORBIDDEN, msg); }
    public static ApiException notFound(String msg)           { return new ApiException(HttpStatus.NOT_FOUND, msg); }
    public static ApiException gone(String msg)               { return new ApiException(HttpStatus.GONE, msg); }
    public static ApiException badRequest(String msg)         { return new ApiException(HttpStatus.BAD_REQUEST, msg); }
    public static ApiException conflict(String msg)           { return new ApiException(HttpStatus.CONFLICT, msg); }
    public static ApiException badGateway(String msg)         { return new ApiException(HttpStatus.BAD_GATEWAY, msg); }
    public static ApiException serviceUnavailable(String msg) { return new ApiException(HttpStatus.SERVICE_UNAVAILABLE, msg); }
    public static ApiException unprocessable(String msg)      { return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, msg); }
}
