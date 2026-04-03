package securepay.app.auth.dto;

import com.securepay.auth.model.RiskLevel;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

/**
 * Risk evaluation result — internal DTO between RiskEvaluatorService and AuthService.
 * Not exposed via API.
 */
@Getter
@Builder
@AllArgsConstructor
public class RiskEvaluation {
    private int score;
    private RiskLevel level;
    private boolean unknownDevice;
    private boolean unusualTime;
    private boolean concurrentSession;
    @Builder.Default
    private boolean evaluationFailed = false;

    /**
     * Human-readable reason for step-up — shown to user via LoginResponse.
     */
    public String getPrimaryReason() {
        if (unknownDevice) return "UNKNOWN_DEVICE";
        if (concurrentSession) return "CONCURRENT_SESSION";
        if (unusualTime) return "UNUSUAL_TIME";
        return null;
    }
}