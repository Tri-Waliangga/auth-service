package com.portfolio.authservice.application.command;

public record TokenCommand(
        String clientId,
        String timestamp,
        String signature,
        String grantType,
        String remoteIp,
        String userAgent,
        String requestId) {
}
