package com.portfolio.authservice;

import com.portfolio.authservice.support.PersistenceBackedServiceMocks;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration"
})
class AuthServiceApplicationTests extends PersistenceBackedServiceMocks {

    @Test
    void contextLoads() {
    }
}
