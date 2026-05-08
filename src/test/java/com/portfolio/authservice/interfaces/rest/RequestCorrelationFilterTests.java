package com.portfolio.authservice.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.FilterChain;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RequestCorrelationFilterTests {

    @Test
    void addsRequestIdToRequestAttributeAndMdcThenClearsMdc() throws Exception {
        RequestCorrelationFilter filter = new RequestCorrelationFilter();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/cashup/v1.0/access-token/b2b");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> requestAttribute = new AtomicReference<>();
        AtomicReference<String> mdcValue = new AtomicReference<>();
        FilterChain filterChain = (servletRequest, servletResponse) -> {
            requestAttribute.set((String) servletRequest.getAttribute(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE));
            mdcValue.set(MDC.get(RequestCorrelationFilter.REQUEST_ID_MDC_KEY));
        };

        filter.doFilter(request, response, filterChain);

        assertThat(requestAttribute.get()).isNotBlank();
        assertThat(UUID.fromString(requestAttribute.get())).isNotNull();
        assertThat(mdcValue.get()).isEqualTo(requestAttribute.get());
        assertThat(MDC.get(RequestCorrelationFilter.REQUEST_ID_MDC_KEY)).isNull();
    }
}
