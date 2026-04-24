package com.loyalty.identity_service;

import com.loyalty.identity_service.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class IdentityServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(IdentityServiceApplication.class, args);
	}
}