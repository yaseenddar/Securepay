package com.securepay.transaction.service;

import java.util.UUID;

import com.securepay.auth.model.RiskLevel;

public class AuthContext {

    private final UUID userId;
    private final RiskLevel riskLevel;
    private final boolean stepUpDone;
    private final String deviceHash;

    public AuthContext(UUID userId, RiskLevel riskLevel,
                       boolean stepUpDone, String deviceHash) {
        this.userId = userId;
        this.riskLevel = riskLevel;
        this.stepUpDone = stepUpDone;
        this.deviceHash = deviceHash;
    }

    public UUID getUserId() {
        return userId;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public boolean isStepUpDone() {
        return stepUpDone;
    }

    public String getDeviceHash() {
        return deviceHash;
    }
}