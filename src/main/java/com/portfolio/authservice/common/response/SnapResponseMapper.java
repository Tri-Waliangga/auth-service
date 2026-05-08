package com.portfolio.authservice.common.response;

import com.portfolio.authservice.application.token.IssuedAccessToken;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BResponse;
import com.portfolio.authservice.interfaces.rest.dto.SnapErrorResponse;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
public class SnapResponseMapper {

    public static final String SUCCESS_RESPONSE_CODE = "2007300";

    private final SnapResponseCodeMapper responseCodeMapper;

    public SnapResponseMapper(SnapResponseCodeMapper responseCodeMapper) {
        this.responseCodeMapper = responseCodeMapper;
    }

    public AccessTokenB2BResponse accessTokenSuccess(IssuedAccessToken issuedToken) {
        return new AccessTokenB2BResponse(
                SUCCESS_RESPONSE_CODE,
                responseCodeMapper.resolveMessage(SUCCESS_RESPONSE_CODE),
                issuedToken.accessToken(),
                issuedToken.tokenType(),
                issuedToken.expiresIn(),
                Map.of());
    }

    public SnapErrorResponse error(String responseCode, String responseMessage) {
        return new SnapErrorResponse(responseCode, responseMessage, Map.of());
    }

    public SnapErrorResponse error(String responseCode) {
        return error(responseCode, responseCodeMapper.resolvePublicMessage(responseCode));
    }

    public ResponseEntity<SnapErrorResponse> errorResponse(String responseCode, String responseMessage) {
        return ResponseEntity.status(httpStatus(responseCode)).body(error(responseCode, responseMessage));
    }

    public ResponseEntity<SnapErrorResponse> errorResponse(String responseCode) {
        return errorResponse(responseCode, responseCodeMapper.resolvePublicMessage(responseCode));
    }

    public HttpStatus httpStatus(String responseCode) {
        try {
            return HttpStatus.valueOf(Integer.parseInt(responseCode.substring(0, 3)));
        } catch (RuntimeException exception) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
    }
}
