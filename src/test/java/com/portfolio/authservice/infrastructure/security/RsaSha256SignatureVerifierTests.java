package com.portfolio.authservice.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.support.TestCryptoFixtures;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

class RsaSha256SignatureVerifierTests {

    private RsaSha256SignatureVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = new RsaSha256SignatureVerifier(responseCodeMapper());
    }

    @Test
    void verifiesValidAccessTokenB2BSignatureWithPublicKeyPem() {
        boolean valid = verifier.verifyAuthSignature(
                TestCryptoFixtures.CLIENT_ID,
                TestCryptoFixtures.TIMESTAMP,
                TestCryptoFixtures.AUTH_SIGNATURE,
                TestCryptoFixtures.PUBLIC_KEY_PEM);

        assertThat(valid).isTrue();
    }

    @Test
    void verifiesValidSignatureWithExplicitStringToSign() {
        boolean valid = verifier.verifySignature(
                TestCryptoFixtures.EXPLICIT_STRING_TO_SIGN,
                TestCryptoFixtures.EXPLICIT_SIGNATURE,
                TestCryptoFixtures.PUBLIC_KEY_PEM);

        assertThat(valid).isTrue();
    }

    @Test
    void rejectsBlankStringToSign() {
        assertUnauthorized(() -> verifier.verifySignature(" ", "signature", TestCryptoFixtures.PUBLIC_KEY_PEM));
    }

    @Test
    void verifiesValidSignatureWithClientCredentialPublicKeyFromDatabase() {
        ClientCredential credential = new ClientCredential(
                1L,
                TestCryptoFixtures.CLIENT_ID,
                "MERCHANT-001",
                "95221",
                900,
                TestCryptoFixtures.PUBLIC_KEY_PEM,
                "SHA256withRSA",
                "key-1",
                List.of("openid"));

        boolean valid = verifier.verifyAuthSignature(
                TestCryptoFixtures.CLIENT_ID,
                TestCryptoFixtures.TIMESTAMP,
                TestCryptoFixtures.AUTH_SIGNATURE,
                credential);

        assertThat(valid).isTrue();
    }

    @Test
    void parsesPublicKeyPemWithLineBreaks() {
        String wrappedPem = TestCryptoFixtures.PUBLIC_KEY_PEM
                .replace("-----BEGIN PUBLIC KEY-----\n", "-----BEGIN PUBLIC KEY-----\r\n");

        boolean valid = verifier.verifyAuthSignature(
                TestCryptoFixtures.CLIENT_ID,
                TestCryptoFixtures.TIMESTAMP,
                TestCryptoFixtures.AUTH_SIGNATURE,
                wrappedPem);

        assertThat(valid).isTrue();
    }

    @Test
    void returnsFalseForDifferentTimestamp() {
        boolean valid = verifier.verifyAuthSignature(
                TestCryptoFixtures.CLIENT_ID,
                "2026-05-07T15:01:00+07:00",
                TestCryptoFixtures.AUTH_SIGNATURE,
                TestCryptoFixtures.PUBLIC_KEY_PEM);

        assertThat(valid).isFalse();
    }

    @Test
    void returnsFalseForSignatureFromDifferentKey() {
        boolean valid = verifier.verifyAuthSignature(
                TestCryptoFixtures.CLIENT_ID,
                TestCryptoFixtures.TIMESTAMP,
                TestCryptoFixtures.OTHER_KEY_AUTH_SIGNATURE,
                TestCryptoFixtures.PUBLIC_KEY_PEM);

        assertThat(valid).isFalse();
    }

    @Test
    void rejectsMalformedBase64Signature() {
        assertUnauthorized(() -> verifier.verifyAuthSignature(
                "client-id",
                "2026-05-07T15:00:00+07:00",
                "not-base64!",
                TestCryptoFixtures.PUBLIC_KEY_PEM));
    }

    @Test
    void rejectsInvalidPublicKeyPem() {
        assertUnauthorized(() -> verifier.verifyAuthSignature(
                TestCryptoFixtures.CLIENT_ID,
                TestCryptoFixtures.TIMESTAMP,
                TestCryptoFixtures.AUTH_SIGNATURE,
                "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----"));
    }

    @Test
    void rejectsMissingPublicKeyPemMarker() {
        String pemWithoutMarkers = TestCryptoFixtures.PUBLIC_KEY_PEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");

        assertUnauthorized(() -> verifier.verifyAuthSignature(
                TestCryptoFixtures.CLIENT_ID,
                TestCryptoFixtures.TIMESTAMP,
                TestCryptoFixtures.AUTH_SIGNATURE,
                pemWithoutMarkers));
    }

    @Test
    void rejectsUnsupportedCredentialAlgorithm() {
        ClientCredential credential = new ClientCredential(
                1L,
                TestCryptoFixtures.CLIENT_ID,
                "MERCHANT-001",
                "95221",
                900,
                TestCryptoFixtures.PUBLIC_KEY_PEM,
                "RS256",
                "key-1",
                List.of("openid"));

        assertUnauthorized(() -> verifier.verifyAuthSignature(
                TestCryptoFixtures.CLIENT_ID,
                TestCryptoFixtures.TIMESTAMP,
                TestCryptoFixtures.AUTH_SIGNATURE,
                credential));
    }

    private void assertUnauthorized(ThrowingRunnable runnable) {
        assertThatThrownBy(runnable::run)
                .isInstanceOfSatisfying(SignatureVerificationException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("4017300");
                    assertThat(exception.getResponseMessage()).isEqualTo("Unauthorized");
                    assertThat(exception.getReason()).isNotBlank();
                });
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
