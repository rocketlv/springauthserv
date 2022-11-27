package ua.com.rocketlv.demoapp;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "auth-server")
@Data
public class AuthClientsProperties {
    private List<User> clients;
}

;
