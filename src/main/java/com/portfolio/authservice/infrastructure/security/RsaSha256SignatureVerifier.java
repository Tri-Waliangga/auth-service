package com.portfolio.authservice.infrastructure.security;

import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.domain.port.SignatureVerifier;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class RsaSha256SignatureVerifier implements SignatureVerifier {

    static final String ALGORITHM = "SHA256withRSA";
    private static final String RSA_KEY_FACTORY = "RSA";
    private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

    private final SnapResponseCodeMapper responseCodeMapper;

    public RsaSha256SignatureVerifier(SnapResponseCodeMapper responseCodeMapper) {
        this.responseCodeMapper = responseCodeMapper;
    }

    @Override
    public boolean verifyAuthSignature(String clientId, String timestamp, String signatureBase64, String publicKeyPem) {
        byte[] signatureBytes = decodeSignature(signatureBase64);
        PublicKey publicKey = parsePublicKey(publicKeyPem);
        byte[] stringToSign = buildStringToSign(clientId, timestamp).getBytes(StandardCharsets.UTF_8);

        try {
            java.security.Signature verifier = java.security.Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(stringToSign);
            return verifier.verify(signatureBytes);
        } catch (GeneralSecurityException exception) {
            throw unauthorized("SIGNATURE_VERIFICATION_FAILED");
        }
    }

    @Override
    public boolean verifyAuthSignature(
            String clientId,
            String timestamp,
            String signatureBase64,
            ClientCredential credential) {
        if (credential == null || !StringUtils.hasText(credential.publicKeyPem())) {
            throw unauthorized("PUBLIC_KEY_MISSING");
        }
        if (!ALGORITHM.equals(credential.publicKeyAlgorithm())) {
            throw unauthorized("UNSUPPORTED_PUBLIC_KEY_ALGORITHM");
        }
        return verifyAuthSignature(clientId, timestamp, signatureBase64, credential.publicKeyPem());
    }

    private String buildStringToSign(String clientId, String timestamp) {
        return clientId + "|" + timestamp;
    }

    private byte[] decodeSignature(String signatureBase64) {
        if (!StringUtils.hasText(signatureBase64)) {
            throw unauthorized("INVALID_SIGNATURE_FORMAT");
        }
        try {
            return Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException exception) {
            throw unauthorized("INVALID_SIGNATURE_FORMAT");
        }
    }

    private PublicKey parsePublicKey(String publicKeyPem) {
        if (!StringUtils.hasText(publicKeyPem)
                || !publicKeyPem.contains(BEGIN_PUBLIC_KEY)
                || !publicKeyPem.contains(END_PUBLIC_KEY)) {
            throw unauthorized("INVALID_PUBLIC_KEY");
        }

        String base64PublicKey = publicKeyPem
                .replace(BEGIN_PUBLIC_KEY, "")
                .replace(END_PUBLIC_KEY, "")
                .replaceAll("\\s", "");

        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            return KeyFactory.getInstance(RSA_KEY_FACTORY).generatePublic(keySpec);
        } catch (IllegalArgumentException | GeneralSecurityException exception) {
            throw unauthorized("INVALID_PUBLIC_KEY");
        }
    }

    private SignatureVerificationException unauthorized(String reason) {
        return new SignatureVerificationException(
                responseCodeMapper.resolvePublicMessage(SignatureVerificationException.UNAUTHORIZED_RESPONSE_CODE),
                reason);
    }
}
