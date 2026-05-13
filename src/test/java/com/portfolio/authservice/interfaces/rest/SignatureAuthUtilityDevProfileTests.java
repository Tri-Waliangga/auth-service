package com.portfolio.authservice.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import com.portfolio.authservice.application.utility.SignatureAuthGenerationService;
import com.portfolio.authservice.support.PersistenceBackedServiceMocks;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("dev")
@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration",
        "auth.internal.api-key=test-internal-key"
})
class SignatureAuthUtilityDevProfileTests extends PersistenceBackedServiceMocks {

    @Test
    void devProfileRegistersSignatureUtility(ApplicationContext context) {
        assertThat(context.getBeansOfType(SignatureAuthUtilityController.class)).hasSize(1);
        assertThat(context.getBeansOfType(SignatureAuthGenerationService.class)).hasSize(1);
    }
}
