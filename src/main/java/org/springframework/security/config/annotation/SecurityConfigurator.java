package org.springframework.security.config.annotation;


// TODO do we need this interface?
/**
 *
 * @author Rob Winch
 *
 * @param <O> The object being built by B
 * @param <B> The SecurityBuilder that builds objects of type O
 */
public interface SecurityConfigurator<O,B extends SecurityBuilder<O>> {
    void init(B builder) throws Exception;

    void configure(B builder) throws Exception;

    B and() throws Exception;

    void setBuilder(B builder);
}
