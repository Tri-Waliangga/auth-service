package com.portfolio.authservice.support;

import com.portfolio.authservice.application.audit.AuditService;
import com.portfolio.authservice.application.credential.ClientCredentialService;
import com.portfolio.authservice.application.signature.InternalSignatureVerificationService;
import com.portfolio.authservice.application.token.JwtTokenService;
import com.portfolio.authservice.application.token.TokenApplicationService;
import com.portfolio.authservice.application.token.TokenIntrospectionService;
import com.portfolio.authservice.application.token.TokenMetadataService;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

public abstract class PersistenceBackedServiceMocks {

    @MockitoBean
    protected AuditService auditService;

    @MockitoBean
    protected ClientCredentialService clientCredentialService;

    @MockitoBean
    protected InternalSignatureVerificationService internalSignatureVerificationService;

    @MockitoBean
    protected JwtTokenService jwtTokenService;

    @MockitoBean
    protected TokenApplicationService tokenApplicationService;

    @MockitoBean
    protected TokenIntrospectionService tokenIntrospectionService;

    @MockitoBean
    protected TokenMetadataService tokenMetadataService;
}
