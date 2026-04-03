package com.securepay.auth.service;

import com.securepay.auth.model.DeviceFingerprint;
import com.securepay.auth.model.RiskLevel;
import com.securepay.auth.model.User;
import com.securepay.auth.repository.AuthSessionRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import securepay.app.auth.dto.RiskEvaluation;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

@Service
public class RiskEvaluatorService {

    private final Executor authExecutor;
    private final AuthSessionRepository sessionRepository;
    private final int unknownDeviceScore;
    private final int unusualTimeScore;
    private final int concurrentSessionScore;
    private final int unusualHourStart;
    private final int unusualHourEnd;

    public RiskEvaluatorService(
            @Qualifier("authExecutor") Executor authExecutor,
            AuthSessionRepository sessionRepository,
            @Value("${auth.risk.unknown-device-score}") int unknownDeviceScore,
            @Value("${auth.risk.unusual-time-score}") int unusualTimeScore,
            @Value("${auth.risk.concurrent-session-score}") int concurrentSessionScore,
            @Value("${auth.risk.unusual-hour-start}") int unusualHourStart,
            @Value("${auth.risk.unusual-hour-end}") int unusualHourEnd
    ) {
        this.authExecutor = authExecutor;
        this.sessionRepository = sessionRepository;
        this.unknownDeviceScore = unknownDeviceScore;
        this.unusualTimeScore = unusualTimeScore;
        this.concurrentSessionScore = concurrentSessionScore;
        this.unusualHourStart = unusualHourStart;
        this.unusualHourEnd = unusualHourEnd;
    }

    public RiskEvaluation evaluate(User user, DeviceFingerprint device) {
        CompletableFuture<Boolean> unknownDeviceFuture = CompletableFuture.supplyAsync(
                () -> isUnknownDevice(device),
                authExecutor
        );

        CompletableFuture<Boolean> unusualTimeFuture = CompletableFuture.supplyAsync(
                this::isUnusualHour,
                authExecutor
        );

        CompletableFuture<Boolean> concurrentSessionFuture = CompletableFuture.supplyAsync(
                () -> sessionRepository.existsConcurrentSessionFromDifferentDevice(
                        user.getId(),
                        device.getDeviceHash(),
                        LocalDateTime.now()
                ),
                authExecutor
        );

        try {
            CompletableFuture
                    .allOf(unknownDeviceFuture, unusualTimeFuture, concurrentSessionFuture)
                    .join();

        } catch (CompletionException ex) {
            return RiskEvaluation.builder()
                    .score(100)
                    .level(RiskLevel.HIGH)
                    .unknownDevice(true)
                    .unusualTime(false)
                    .concurrentSession(false)
                    .evaluationFailed(true)
                    .build();
        }

        boolean isUnknownDevice = unknownDeviceFuture.join();
        boolean isUnusualTime = unusualTimeFuture.join();
        boolean isConcurrentSession = concurrentSessionFuture.join();

        int score = 0;
        if (isUnknownDevice) score += unknownDeviceScore;
        if (isUnusualTime) score += unusualTimeScore;
        if (isConcurrentSession) score += concurrentSessionScore;

        RiskLevel level = RiskLevel.fromScore(score);

        return RiskEvaluation.builder()
                .score(score)
                .level(level)
                .unknownDevice(isUnknownDevice)
                .unusualTime(isUnusualTime)
                .concurrentSession(isConcurrentSession)
                .evaluationFailed(false)
                .build();
    }

    private boolean isUnknownDevice(DeviceFingerprint device) {
        if (device.isTrusted()) return false;
        return device.isNewDevice();
    }

    boolean isUnusualHour() {
        int hour = LocalTime.now().getHour();
        if (unusualHourStart < unusualHourEnd) {
            return hour >= unusualHourStart && hour < unusualHourEnd;
        }
        return hour >= unusualHourStart || hour < unusualHourEnd;
    }
}
