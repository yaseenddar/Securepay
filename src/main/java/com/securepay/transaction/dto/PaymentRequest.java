package com.securepay.transaction.dto;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;

@Data
@Builder
public class PaymentRequest {
    private String idempotencyKey;
    private String payerUserId;
    private String payeeVpa;
    private double amount;
    private String currency;
    private PaymentStatus status;
    private String riskLevel;
    private String deviceHash;
    private boolean stepUpRequired;
}