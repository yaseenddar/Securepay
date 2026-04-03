package securepay.app.auth.dto;

import lombok.Builder;
import lombok.Getter;

/**
 * Successful registration response.
 */
@Getter
@Builder
public class RegisterResponse {
    private String userId;
    private String message;
}
