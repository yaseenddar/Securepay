package securepay.app.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

/**
 * Token refresh request.
 */
@Getter
public class RefreshRequest {
    @NotBlank
    public String refreshToken;
}
