package securepay.app.auth.dto;


import com.securepay.auth.model.RiskLevel;

import jakarta.validation.constraints.*;
import lombok.*;


/**
 * Device context — extracted from request, never sent by client directly as JSON.
 * Populated by DeviceFingerprintService from HTTP request headers.
 *
 * WHY a separate DTO and not just pass HttpServletRequest around?
 * Testability. Services should not depend on servlet API.
 * DeviceContext is a pure POJO — easily mocked in tests.
 */
@Getter
@Builder
@AllArgsConstructor
public class DeviceContext {
    private String deviceHash;         // SHA-256 computed from below fields
    private String userAgent;
    private String ipSubnet;           // /24 subnet extracted from remote IP
    private String timezone;           // from X-Timezone header or Accept-Language
    private String rawIp;              // stored temporarily for logging only
}
