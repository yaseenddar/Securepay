package com.securepay;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {"com.securepay", "securepay.app.auth"})
public class SecurepayApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurepayApplication.class, args);
	}

}
