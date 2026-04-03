package securepay.app.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

/**
 * Login request.
 * X-Device-Fingerprint comes from HTTP header, not body.
 * DeviceContext is extracted separately in AuthController.
 */
@Getter
public class LoginRequest {
    @NotBlank
    @Email
    public String email;

    @NotBlank
    public String password;
}

