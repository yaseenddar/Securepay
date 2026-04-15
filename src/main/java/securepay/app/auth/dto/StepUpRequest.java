package securepay.app.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;

/**
 * Step-up auth — TOTP code submission.
 * 6-digit numeric code from Google Authenticator or compatible app.
 */
@Getter
public class StepUpRequest {
    @NotBlank
    @Pattern(regexp = "^\\d{6}$", message = "TOTP must be 6 digits")
    public String totpCode;
}
