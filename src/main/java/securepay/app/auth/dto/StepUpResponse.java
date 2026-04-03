package securepay.app.auth.dto;

import lombok.Builder;
import lombok.Getter;

/**
 * Step-up response — new access token with elevated trust claim.
 */
@Getter
@Builder
public class StepUpResponse {
    private String accessToken;
    private long accessTokenExpiresIn;
}
