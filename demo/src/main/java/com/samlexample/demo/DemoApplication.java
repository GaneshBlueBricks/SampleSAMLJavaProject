package com.samlexample.demo;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		try {
			InitializationService.initialize();
		} catch (InitializationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		SpringApplication.run(DemoApplication.class, args);
	}

}
