package com.securepay.transaction.model;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

//─────────────────────────────────────────────────────────────────────────────
//OUTBOX EVENT — insert only
//─────────────────────────────────────────────────────────────────────────────

/**
* Transactional outbox event.
*
* Written in the SAME transaction as domain changes.
* OutboxPublisher polls this table and publishes to Kafka.
*
* RETRY SEMANTICS:
* retry_count tracks how many times publishing was attempted.
* After 5 retries: mark as dead letter, stop retrying, alert.
* last_error stores the last exception message for debugging.
*
* ORDERING GUARANTEE:
* Events are published in created_at order.
* Kafka partition key = aggregate_id (paymentId).
* All events for same payment go to same Kafka partition → ordered.
*/
@Entity
@Table(name = "outbox_events", schema = "txn")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OutboxEvent {

 @Id
 @GeneratedValue(strategy = GenerationType.UUID)
 private UUID id;

 @Column(name = "aggregate_type", nullable = false, length = 50, updatable = false)
 private String aggregateType;   // "PAYMENT"

 @Column(name = "aggregate_id", nullable = false, updatable = false)
 private UUID aggregateId;       // paymentId

 @Column(name = "event_type", nullable = false, length = 100, updatable = false)
 private String eventType;       // "PAYMENT_SUCCESS", "PAYMENT_FAILED" etc.

 @Column(nullable = false, length = 100, updatable = false)
 private String topic;           // Kafka topic

 @Column(nullable = false, columnDefinition = "JSONB", updatable = false)
 @JdbcTypeCode(SqlTypes.JSON)
 private String payload;         // JSON string

 @Column(nullable = false)
 private boolean published = false;

 @Column(name = "retry_count", nullable = false)
 private int retryCount = 0;

 @Column(name = "last_error")
 private String lastError;

 @Column(name = "created_at", updatable = false)
 private LocalDateTime createdAt = LocalDateTime.now();

 @Column(name = "published_at")
 private LocalDateTime publishedAt;

 // ── Domain methods ────────────────────────────────────────────────────────

 public void markPublished() {
     this.published = true;
     this.publishedAt = LocalDateTime.now();
 }

 public void recordFailure(String error) {
     this.retryCount++;
     this.lastError = error;
 }

 public boolean isDeadLetter() {
     return retryCount >= 5;
 }
}