package securepay.app.auth.controller;

import com.securepay.auth.filter.JwtAuthFilter;
import com.securepay.auth.service.AuthService;
import com.securepay.auth.service.DeviceFingerprintService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import securepay.app.auth.dto.LoginRequest;
import securepay.app.auth.dto.LoginResponse;
import securepay.app.auth.dto.RefreshRequest;
import securepay.app.auth.dto.RegisterRequest;
import securepay.app.auth.dto.RegisterResponse;
import securepay.app.auth.dto.StepUpRequest;
import securepay.app.auth.dto.StepUpResponse;

/**
 * Auth HTTP API — delegates to {@link AuthService}.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final DeviceFingerprintService deviceFingerprintService;

    public AuthController(AuthService authService,
                          DeviceFingerprintService deviceFingerprintService) {
        this.authService = authService;
        this.deviceFingerprintService = deviceFingerprintService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(authService.login(
                request,
                deviceFingerprintService.extractFromRequest(httpRequest)));
    }

    @PostMapping("/step-up")
    public ResponseEntity<StepUpResponse> stepUp(
            @Valid @RequestBody StepUpRequest request,
            HttpServletRequest httpRequest
    ) {
        String jti = (String) httpRequest.getAttribute(JwtAuthFilter.ATTR_JTI);
        if (jti == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(authService.completeStepUp(jti, request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @Valid @RequestBody RefreshRequest request
    ) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest httpRequest) {
        String jti = (String) httpRequest.getAttribute(JwtAuthFilter.ATTR_JTI);
        if (jti != null) {
            authService.logout(jti);
        }
        return ResponseEntity.noContent().build();
    }
}
