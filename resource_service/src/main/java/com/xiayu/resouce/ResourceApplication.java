package com.xiayu.resouce;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * @author xuhongyu
 * @create 2023-03-10 15:00
 */


@EnableWebSecurity
@SpringBootApplication
public class ResourceApplication {
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(ResourceApplication.class);
        application.run(args);
    }
}
