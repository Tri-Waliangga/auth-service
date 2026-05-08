package com.portfolio.authservice.domain.port;

import com.portfolio.authservice.application.credential.ClientCredential;

public interface SignatureVerifier {

    boolean verifySignature(String stringToSign, String signatureBase64, String publicKeyPem);

    boolean verifyAuthSignature(String clientId, String timestamp, String signatureBase64, String publicKeyPem);

    boolean verifyAuthSignature(String clientId, String timestamp, String signatureBase64, ClientCredential credential);
}
