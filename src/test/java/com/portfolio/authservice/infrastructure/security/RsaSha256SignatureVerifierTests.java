package com.portfolio.authservice.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

class RsaSha256SignatureVerifierTests {

    private RsaSha256SignatureVerifier verifier;
    private KeyPair keyPair;
    private String publicKeyPem;

    @BeforeEach
    void setUp() throws Exception {
        verifier = new RsaSha256SignatureVerifier(responseCodeMapper());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        publicKeyPem = toPublicKeyPem(keyPair);
    }

    @Test
    void verifiesValidSignatureWithPublicKeyPem() throws Exception {
        String timestamp = "2026-05-07T15:00:00+07:00";
        String signature = sign("client-id|" + timestamp, keyPair.getPrivate());

        boolean valid = verifier.verifyAuthSignature("client-id", timestamp, signature, publicKeyPem);

        assertThat(valid).isTrue();
    }

    @Test
    void verifiesValidSignatureWithExplicitStringToSign() throws Exception {
        String stringToSign = "custom-string-to-sign";
        String signature = sign(stringToSign, keyPair.getPrivate());

        boolean valid = verifier.verifySignature(stringToSign, signature, publicKeyPem);

        assertThat(valid).isTrue();
    }

    @Test
    void rejectsBlankStringToSign() {
        assertUnauthorized(() -> verifier.verifySignature(" ", "signature", publicKeyPem));
    }

    @Test
    void verifiesValidSignatureWithClientCredentialPublicKeyFromDatabase() throws Exception {
        String timestamp = "2026-05-07T15:00:00+07:00";
        String signature = sign("client-id|" + timestamp, keyPair.getPrivate());
        ClientCredential credential = new ClientCredential(
                1L,
                "client-id",
                "MERCHANT-001",
                "95221",
                900,
                publicKeyPem,
                "SHA256withRSA",
                "key-1",
                List.of("openid"));

        boolean valid = verifier.verifyAuthSignature("client-id", timestamp, signature, credential);

        assertThat(valid).isTrue();
    }

    @Test
    void parsesPublicKeyPemWithLineBreaks() throws Exception {
        String timestamp = "2026-05-07T15:00:00+07:00";
        String signature = sign("client-id|" + timestamp, keyPair.getPrivate());
        String wrappedPem = publicKeyPem.replace("-----BEGIN PUBLIC KEY-----\n", "-----BEGIN PUBLIC KEY-----\r\n");

        boolean valid = verifier.verifyAuthSignature("client-id", timestamp, signature, wrappedPem);

        assertThat(valid).isTrue();
    }

    @Test
    void returnsFalseForDifferentTimestamp() throws Exception {
        String signature = sign("client-id|2026-05-07T15:00:00+07:00", keyPair.getPrivate());

        boolean valid = verifier.verifyAuthSignature("client-id", "2026-05-07T15:01:00+07:00", signature, publicKeyPem);

        assertThat(valid).isFalse();
    }

    @Test
    void returnsFalseForSignatureFromDifferentKey() throws Exception {
        KeyPair otherKeyPair = generateKeyPair();
        String timestamp = "2026-05-07T15:00:00+07:00";
        String signature = sign("client-id|" + timestamp, otherKeyPair.getPrivate());

        boolean valid = verifier.verifyAuthSignature("client-id", timestamp, signature, publicKeyPem);

        assertThat(valid).isFalse();
    }

    @Test
    void rejectsMalformedBase64Signature() {
        assertUnauthorized(() -> verifier.verifyAuthSignature(
                "client-id",
                "2026-05-07T15:00:00+07:00",
                "not-base64!",
                publicKeyPem));
    }

    @Test
    void rejectsInvalidPublicKeyPem() throws Exception {
        String timestamp = "2026-05-07T15:00:00+07:00";
        String signature = sign("client-id|" + timestamp, keyPair.getPrivate());

        assertUnauthorized(() -> verifier.verifyAuthSignature(
                "client-id",
                timestamp,
                signature,
                "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----"));
    }

    @Test
    void rejectsMissingPublicKeyPemMarker() throws Exception {
        String timestamp = "2026-05-07T15:00:00+07:00";
        String signature = sign("client-id|" + timestamp, keyPair.getPrivate());
        String pemWithoutMarkers = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");

        assertUnauthorized(() -> verifier.verifyAuthSignature("client-id", timestamp, signature, pemWithoutMarkers));
    }

    @Test
    void rejectsUnsupportedCredentialAlgorithm() throws Exception {
        String timestamp = "2026-05-07T15:00:00+07:00";
        String signature = sign("client-id|" + timestamp, keyPair.getPrivate());
        ClientCredential credential = new ClientCredential(
                1L,
                "client-id",
                "MERCHANT-001",
                "95221",
                900,
                publicKeyPem,
                "RS256",
                "key-1",
                List.of("openid"));

        assertUnauthorized(() -> verifier.verifyAuthSignature("client-id", timestamp, signature, credential));
    }

    private void assertUnauthorized(ThrowingRunnable runnable) {
        assertThatThrownBy(runnable::run)
                .isInstanceOfSatisfying(SignatureVerificationException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("4017300");
                    assertThat(exception.getResponseMessage()).isEqualTo("Unauthorized");
                    assertThat(exception.getReason()).isNotBlank();
                });
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private String sign(String value, PrivateKey privateKey) throws Exception {
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(value.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private String toPublicKeyPem(KeyPair pair) {
        String encodedKey = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(pair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encodedKey + "\n-----END PUBLIC KEY-----";
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
