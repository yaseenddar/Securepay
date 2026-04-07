package com.securepay.transaction.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

import lombok.Builder;
import lombok.Data;


@Data
@Builder
public class PaymentResponse {

    private UUID paymentId;
    private String idempotencyKey;
    private PaymentStatus status;
    private BigDecimal amount;
    private String payeeVpa;
    private boolean stepUpRequired;
    private String failureReason;
    private LocalDateTime initiatedAt;
    private LocalDateTime completedAt;
}