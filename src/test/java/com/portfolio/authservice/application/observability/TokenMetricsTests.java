package com.portfolio.authservice.application.observability;

import static org.assertj.core.api.Assertions.assertThat;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TokenMetricsTests {

    private SimpleMeterRegistry meterRegistry;
    private TokenMetrics tokenMetrics;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        tokenMetrics = new TokenMetrics(meterRegistry);
    }

    @Test
    void countersIncrementIndependently() {
        tokenMetrics.recordSuccess();
        tokenMetrics.recordFailure();
        tokenMetrics.recordInvalidSignature();
        tokenMetrics.recordUnauthorized();

        assertThat(counterCount(TokenMetrics.TOKEN_REQUEST_SUCCESS)).isEqualTo(1.0);
        assertThat(counterCount(TokenMetrics.TOKEN_REQUEST_FAILURE)).isEqualTo(1.0);
        assertThat(counterCount(TokenMetrics.TOKEN_INVALID_SIGNATURE)).isEqualTo(1.0);
        assertThat(counterCount(TokenMetrics.TOKEN_UNAUTHORIZED)).isEqualTo(1.0);
    }

    @Test
    void latencyTimerRecordsCompletedSamples() {
        Timer.Sample sample = tokenMetrics.startLatencyTimer();

        tokenMetrics.recordLatency(sample);

        assertThat(meterRegistry.timer(TokenMetrics.TOKEN_REQUEST_LATENCY).count()).isEqualTo(1L);
        assertThat(meterRegistry.timer(TokenMetrics.TOKEN_REQUEST_LATENCY).totalTime(java.util.concurrent.TimeUnit.NANOSECONDS))
                .isGreaterThanOrEqualTo(0.0);
    }

    @Test
    void metersDoNotUseSensitiveTags() {
        tokenMetrics.recordSuccess();
        tokenMetrics.recordFailure();
        tokenMetrics.recordInvalidSignature();
        tokenMetrics.recordUnauthorized();
        tokenMetrics.recordLatency(tokenMetrics.startLatencyTimer());

        Set<String> tagKeys = meterRegistry.getMeters().stream()
                .map(Meter::getId)
                .flatMap(id -> id.getTags().stream())
                .map(tag -> tag.getKey().toLowerCase())
                .collect(Collectors.toSet());

        assertThat(tagKeys).doesNotContain(
                "clientid",
                "client_id",
                "token",
                "signature",
                "secret",
                "requestid",
                "request_id",
                "ip",
                "useragent",
                "user_agent");
    }

    private double counterCount(String meterName) {
        return meterRegistry.counter(meterName).count();
    }
}
