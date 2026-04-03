package securepay.app.auth.dto;

import com.securepay.auth.model.RiskLevel;

import lombok.Builder;
import lombok.Getter;

//─────────────────────────────────────────────────────────────────────────────
//RESPONSE DTOs
//─────────────────────────────────────────────────────────────────────────────

/**
* Login response — the most important DTO in the service.
*
* stepUpRequired: tells client it MUST call /step-up before
*   high-value actions will be permitted by Transaction Service.
*
* stepUpReason: client uses this to show the user WHY they're
*   being asked for extra verification. UX matters for security adoption.
*
* riskLevel: embedded in JWT claims too, but returned here
*   so client can adapt UI accordingly (e.g., show security notice).
*/
@Getter
@Builder
public class LoginResponse {
 private String accessToken;
 private String refreshToken;
 private RiskLevel riskLevel;
 private boolean stepUpRequired;
 private String stepUpReason;        // "UNKNOWN_DEVICE" | "UNUSUAL_TIME" | "CONCURRENT_SESSION"
 private long accessTokenExpiresIn;  // milliseconds — client uses this for token refresh scheduling
}