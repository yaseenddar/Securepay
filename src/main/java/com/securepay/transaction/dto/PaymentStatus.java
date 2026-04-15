package com.securepay.transaction.dto;

import com.securepay.transaction.exception.IllegalStateTransitionException;

import java.util.Map;
import java.util.Set;

/**
 * Payment lifecycle state machine.
 *
 * STATES:
 * INITIATED      — payment request received, not yet evaluated
 * RISK_EVALUATED — fraud engine has scored this payment
 * AUTH_PENDING   — high-value payment waiting for step-up confirmation
 * BLOCKED        — fraud engine blocked this payment (terminal)
 * PROCESSING     — deducting balance, writing ledger entries
 * SUCCESS        — payment complete, ledger entries written (terminal)
 * FAILED         — processing failed — insufficient funds, timeout etc. (terminal)
 * REVERSED       — previously succeeded, now reversed (terminal)
 *
 * TERMINAL STATES: BLOCKED, SUCCESS, FAILED, REVERSED
 * No transitions out of terminal states.
 * Terminal payments are immutable — any mutation attempt throws.
 *
 * WHY encode transitions in the enum itself?
 * State transition logic belongs to the state, not the service.
 * Service calls payment.getStatus().transitionTo(newStatus).
 * The enum is the authority on what's legal — not scattered if-else in services.
 * If you add a new state, you add it here and the compiler forces you to
 * update the transitions map — can't forget.
 */
public enum PaymentStatus {

    INITIATED,
    RISK_EVALUATED,
    AUTH_PENDING,
    BLOCKED,
    PROCESSING,
    SUCCESS,
    FAILED,
    REVERSED;

    // ── Transition table ──────────────────────────────────────────────────────
    // Map.of is immutable — thread-safe, no defensive copying needed
    // Set.of is immutable — same benefit
    private static final Map<PaymentStatus, Set<PaymentStatus>> ALLOWED_TRANSITIONS =
            Map.of(
                    INITIATED,      Set.of(RISK_EVALUATED),
                    RISK_EVALUATED, Set.of(AUTH_PENDING, BLOCKED, PROCESSING),
                    // RISK_EVALUATED → PROCESSING: low-risk payments skip AUTH_PENDING
                    // RISK_EVALUATED → AUTH_PENDING: high-risk requires step-up
                    // RISK_EVALUATED → BLOCKED: fraud engine blocks it
                    AUTH_PENDING,   Set.of(PROCESSING),
                    PROCESSING,     Set.of(SUCCESS, FAILED, REVERSED),
                    BLOCKED,        Set.of(),   // terminal
                    SUCCESS,        Set.of(),   // terminal
                    FAILED,         Set.of(),   // terminal
                    REVERSED,       Set.of()    // terminal
            );

    /**
     * Check if transition to next is legal.
     */
    public boolean canTransitionTo(PaymentStatus next) {
        return ALLOWED_TRANSITIONS
                .getOrDefault(this, Set.of())
                .contains(next);
    }

    /**
     * Attempt transition — returns next status if legal, throws if not.
     *
     * Caller pattern:
     *   payment.setStatus(payment.getStatus().transitionTo(PROCESSING));
     *
     * WHY return the new status instead of void?
     * Forces the caller to assign the result — can't accidentally call
     * transitionTo() and forget to update the field.
     * "payment.getStatus().transitionTo(PROCESSING)" — if you don't assign
     * this to payment.status, the IDE warns about unused return value.
     */
    public PaymentStatus transitionTo(PaymentStatus next) {
        System.out.println("PPPPPPPPPPPPPPPPPPPPPPPPPPPPP Status check {} "+next);
        if (!canTransitionTo(next)) {
            throw new IllegalStateTransitionException(
                    "Illegal payment state transition: " + this + " → " + next
            );
        }
        return next;
    }

    /**
     * Terminal states have no outgoing transitions.
     * Terminal payments must never be mutated.
     */
    public boolean isTerminal() {
        return ALLOWED_TRANSITIONS
                .getOrDefault(this, Set.of())
                .isEmpty();
    }
}
