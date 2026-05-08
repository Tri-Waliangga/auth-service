package com.portfolio.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "auth.jwt")
public class JwtProperties {

    private String issuer = "auth-service";
    private String privateKey;
    private String publicKey;
    private Integer defaultTokenTtlSeconds = 900;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public Integer getDefaultTokenTtlSeconds() {
        return defaultTokenTtlSeconds;
    }

    public void setDefaultTokenTtlSeconds(Integer defaultTokenTtlSeconds) {
        this.defaultTokenTtlSeconds = defaultTokenTtlSeconds;
    }
}
