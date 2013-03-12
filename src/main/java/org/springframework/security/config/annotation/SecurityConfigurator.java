package org.springframework.security.config.annotation;


// TODO do we need this interface?
public interface SecurityConfigurator<B extends SecurityBuilder<?>> {
    void init(B builder) throws Exception;

    void configure(B builder) throws Exception;

    B and() throws Exception;

    void setBuilder(B builder);
}
