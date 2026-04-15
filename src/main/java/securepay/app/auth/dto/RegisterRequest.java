package securepay.app.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

//─────────────────────────────────────────────────────────────────────────────
//REQUEST DTOs
//─────────────────────────────────────────────────────────────────────────────

/**
* Registration request.
* @NotBlank on all fields — empty strings must fail at controller level,
* not reach service layer. Fail fast principle.
*/
@Getter
public class RegisterRequest {
 @NotBlank(message = "Email is required")
 @Email(message = "Invalid email format")
 public String email;

 @NotBlank(message = "Phone is required")
 @Pattern(regexp = "^[6-9]\\d{9}$", message = "Invalid Indian mobile number")
 public String phone;

 @NotBlank
 @Size(min = 8, message = "Password must be at least 8 characters")
 public String password;
}

