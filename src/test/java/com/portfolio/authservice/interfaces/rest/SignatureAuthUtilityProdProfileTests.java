package com.portfolio.authservice.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import com.portfolio.authservice.application.utility.SignatureAuthGenerationService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("prod")
@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration",
        "AUTH_DB_URL=jdbc:mysql://prod-db:3306/auth_db",
        "AUTH_DB_USERNAME=prod-user",
        "AUTH_DB_PASSWORD=prod-password",
        "AUTH_JWT_PRIVATE_KEY=test-private-key",
        "AUTH_JWT_PUBLIC_KEY=test-public-key",
        "AUTH_INTERNAL_API_KEY=test-internal-key"
})
class SignatureAuthUtilityProdProfileTests {

    @Test
    void prodProfileDoesNotRegisterSignatureUtility(ApplicationContext context) {
        assertThat(context.getBeansOfType(SignatureAuthUtilityController.class)).isEmpty();
        assertThat(context.getBeansOfType(SignatureAuthGenerationService.class)).isEmpty();
    }
}
