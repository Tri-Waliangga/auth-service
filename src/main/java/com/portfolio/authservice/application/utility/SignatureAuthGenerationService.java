package com.portfolio.authservice.application.utility;

import com.portfolio.authservice.common.error.SnapValidationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.interfaces.rest.dto.SignatureAuthGenerateResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@Profile({"dev", "local"})
public class SignatureAuthGenerationService {

    static final String ALGORITHM = "SHA256withRSA";

    private static final String INVALID_MANDATORY_FIELD_CODE = "4007302";
    private static final String INVALID_FIELD_FORMAT_CODE = "4007301";
    private static final String RSA_KEY_FACTORY = "RSA";
    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    private final SnapResponseCodeMapper responseCodeMapper;

    public SignatureAuthGenerationService(SnapResponseCodeMapper responseCodeMapper) {
        this.responseCodeMapper = responseCodeMapper;
    }

    public SignatureAuthGenerateResponse generate(String clientId, String timestamp, String privateKeyPem) {
        validateMandatory("clientId", clientId);
        validateMandatory("timestamp", timestamp);
        validateMandatory("privateKeyPem", privateKeyPem);

        String stringToSign = clientId + "|" + timestamp;
        try {
            java.security.Signature signer = java.security.Signature.getInstance(ALGORITHM);
            signer.initSign(parsePrivateKey(privateKeyPem));
            signer.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.getEncoder().encodeToString(signer.sign());
            return new SignatureAuthGenerateResponse(
                    signature,
                    stringToSign,
                    ALGORITHM,
                    Map.of("developmentOnly", true));
        } catch (GeneralSecurityException exception) {
            throw invalidPrivateKey();
        }
    }

    private void validateMandatory(String fieldName, String value) {
        if (!StringUtils.hasText(value)) {
            throw new SnapValidationException(
                    INVALID_MANDATORY_FIELD_CODE,
                    responseCodeMapper.resolveMessage(INVALID_MANDATORY_FIELD_CODE, fieldName),
                    "Invalid mandatory field: " + fieldName);
        }
    }

    private RSAPrivateKey parsePrivateKey(String privateKeyPem) {
        if (!privateKeyPem.contains(BEGIN_PRIVATE_KEY) || !privateKeyPem.contains(END_PRIVATE_KEY)) {
            throw invalidPrivateKey();
        }

        String base64PrivateKey = privateKeyPem
                .replace("\\n", "\n")
                .replace(BEGIN_PRIVATE_KEY, "")
                .replace(END_PRIVATE_KEY, "")
                .replaceAll("\\s", "");

        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(base64PrivateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return (RSAPrivateKey) KeyFactory.getInstance(RSA_KEY_FACTORY).generatePrivate(keySpec);
        } catch (IllegalArgumentException | GeneralSecurityException exception) {
            throw invalidPrivateKey();
        }
    }

    private SnapValidationException invalidPrivateKey() {
        return new SnapValidationException(
                INVALID_FIELD_FORMAT_CODE,
                responseCodeMapper.resolveMessage(INVALID_FIELD_FORMAT_CODE, "privateKeyPem"),
                "Invalid field format: privateKeyPem");
    }
}
