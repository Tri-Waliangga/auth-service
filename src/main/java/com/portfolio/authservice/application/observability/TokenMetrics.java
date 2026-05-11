package com.portfolio.authservice.application.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

@Component
public class TokenMetrics {

    public static final String TOKEN_REQUEST_SUCCESS = "auth.token.request.success";
    public static final String TOKEN_REQUEST_FAILURE = "auth.token.request.failure";
    public static final String TOKEN_INVALID_SIGNATURE = "auth.token.invalid.signature";
    public static final String TOKEN_UNAUTHORIZED = "auth.token.unauthorized";
    public static final String TOKEN_REQUEST_LATENCY = "auth.token.request.latency";

    private final MeterRegistry meterRegistry;
    private final Counter successCounter;
    private final Counter failureCounter;
    private final Counter invalidSignatureCounter;
    private final Counter unauthorizedCounter;
    private final Timer latencyTimer;

    public TokenMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.successCounter = Counter.builder(TOKEN_REQUEST_SUCCESS)
                .description("Successful B2B access token requests")
                .register(meterRegistry);
        this.failureCounter = Counter.builder(TOKEN_REQUEST_FAILURE)
                .description("Failed B2B access token requests")
                .register(meterRegistry);
        this.invalidSignatureCounter = Counter.builder(TOKEN_INVALID_SIGNATURE)
                .description("B2B access token requests rejected because of invalid signatures")
                .register(meterRegistry);
        this.unauthorizedCounter = Counter.builder(TOKEN_UNAUTHORIZED)
                .description("Unauthorized B2B access token requests")
                .register(meterRegistry);
        this.latencyTimer = Timer.builder(TOKEN_REQUEST_LATENCY)
                .description("B2B access token request latency")
                .register(meterRegistry);
    }

    public Timer.Sample startLatencyTimer() {
        return Timer.start(meterRegistry);
    }

    public void recordLatency(Timer.Sample sample) {
        sample.stop(latencyTimer);
    }

    public void recordSuccess() {
        successCounter.increment();
    }

    public void recordFailure() {
        failureCounter.increment();
    }

    public void recordInvalidSignature() {
        invalidSignatureCounter.increment();
    }

    public void recordUnauthorized() {
        unauthorizedCounter.increment();
    }
}
