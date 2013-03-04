package org.springframework.security.config.annotation;


public interface SecurityConfigurator<B extends SecurityBuilder<?>> {
    void init(B builder) throws Exception;

    void configure(B builder) throws Exception;
}
