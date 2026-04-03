package com.securepay.auth.model;


/**
 * Risk level assigned at login time based on device, time, and session signals.
 *
 * Used in two places:
 * 1. Stored in AuthSession — persisted record of what risk was assessed
 * 2. Embedded in JWT claims — downstream services read this to gate actions
 *
 * SCORE THRESHOLDS (see RiskEvaluatorService):
 *   0–29  → LOW    → proceed normally
 *   30–59 → MEDIUM → flag, allow with warning
 *   60+   → HIGH   → step-up auth required before token is fully trusted
 */
public enum RiskLevel {
    LOW, MEDIUM, HIGH;

    public static RiskLevel fromScore(int score) {
        if (score < 30) return LOW;
        if (score < 60) return MEDIUM;
        return HIGH;
    }

    public boolean requiresStepUp() {
        return this == HIGH;
    }
}
