package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.application.token.TokenIntrospectionService;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.TokenIntrospectionRequest;
import com.portfolio.authservice.interfaces.rest.dto.TokenIntrospectionResponse;
import jakarta.validation.Valid;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnBean({
        OauthAccessTokenJpaRepository.class,
        TokenIntrospectionService.class
})
public class TokenIntrospectionController {

    private final TokenIntrospectionService tokenIntrospectionService;

    public TokenIntrospectionController(TokenIntrospectionService tokenIntrospectionService) {
        this.tokenIntrospectionService = tokenIntrospectionService;
    }

    @PostMapping(path = "/internal/v1.0/tokens/introspect", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenIntrospectionResponse> introspect(
            @Valid @RequestBody TokenIntrospectionRequest request) {
        return ResponseEntity.ok(tokenIntrospectionService.introspect(request.token()));
    }
}
