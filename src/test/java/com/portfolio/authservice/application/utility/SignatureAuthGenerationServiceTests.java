package com.portfolio.authservice.application.utility;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.common.error.SnapValidationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.SignatureAuthGenerateResponse;
import com.portfolio.authservice.support.TestCryptoFixtures;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

class SignatureAuthGenerationServiceTests {

    private SignatureAuthGenerationService service;

    @BeforeEach
    void setUp() {
        service = new SignatureAuthGenerationService(responseCodeMapper());
    }

    @Test
    void generatesBase64SignatureThatVerifiesWithMatchingPublicKey() throws Exception {
        SignatureAuthGenerateResponse response = service.generate(
                "client-id",
                "2026-05-10T12:00:00+07:00",
                TestCryptoFixtures.PRIVATE_KEY_PEM);

        assertThat(response.signature()).isNotBlank();
        assertThat(response.stringToSign()).isEqualTo("client-id|2026-05-10T12:00:00+07:00");
        assertThat(response.algorithm()).isEqualTo("SHA256withRSA");
        assertThat(response.additionalInfo()).containsEntry("developmentOnly", true);
        assertThat(verify(response.stringToSign(), response.signature(), TestCryptoFixtures.publicKey())).isTrue();
    }

    @Test
    void rejectsMissingClientIdAsMandatoryField() {
        assertThatThrownBy(() -> service.generate(
                " ",
                "2026-05-10T12:00:00+07:00",
                TestCryptoFixtures.PRIVATE_KEY_PEM))
                .isInstanceOfSatisfying(SnapValidationException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("4007302");
                    assertThat(exception.getResponseMessage()).contains("clientId");
                    assertThat(exception.getReason()).isEqualTo("Invalid mandatory field: clientId");
                });
    }

    @Test
    void rejectsMalformedPrivateKeyAsInvalidFieldFormat() {
        assertThatThrownBy(() -> service.generate(
                "client-id",
                "2026-05-10T12:00:00+07:00",
                "not-a-private-key"))
                .isInstanceOfSatisfying(SnapValidationException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("4007301");
                    assertThat(exception.getResponseMessage()).contains("privateKeyPem");
                    assertThat(exception.getReason()).isEqualTo("Invalid field format: privateKeyPem");
                });
    }

    private boolean verify(String stringToSign, String signatureBase64, PublicKey publicKey) throws Exception {
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(stringToSign.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(Base64.getDecoder().decode(signatureBase64));
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }
}
