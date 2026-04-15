package securepay.app.auth.controller;

import com.securepay.auth.model.DeviceFingerprint;
import com.securepay.auth.model.User;
import com.securepay.auth.repository.AuthSessionRepository;
import com.securepay.auth.repository.DeviceFingerprintRepository;
import com.securepay.auth.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/v1/auth/devices")
public class DeviceController {

    private final DeviceFingerprintRepository deviceFingerprintRepository;
    private final AuthSessionRepository authSessionRepository;
    private final UserRepository userRepository;

    public DeviceController(
            DeviceFingerprintRepository deviceFingerprintRepository,
            AuthSessionRepository authSessionRepository,
            UserRepository userRepository
    ) {
        this.deviceFingerprintRepository = deviceFingerprintRepository;
        this.authSessionRepository = authSessionRepository;
        this.userRepository = userRepository;
    }

    @GetMapping
    public ResponseEntity<List<DeviceFingerprint>> listDevices(
            @AuthenticationPrincipal UserDetails principal
    ) {
        User user = userRepository.findByEmail(principal.getUsername()).orElseThrow();
        return ResponseEntity.ok(deviceFingerprintRepository.findAllByUserId(user.getId()));
    }

    @DeleteMapping("/{deviceHash}")
    public ResponseEntity<Void> revokeDevice(
            @PathVariable String deviceHash,
            @AuthenticationPrincipal UserDetails principal
    ) {
        User user = userRepository.findByEmail(principal.getUsername()).orElseThrow();
        authSessionRepository.revokeAllByUserIdAndDeviceHash(
                user.getId(), deviceHash, LocalDateTime.now());
        return ResponseEntity.noContent().build();
    }
}
