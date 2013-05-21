package org.springframework.security.config.annotation;

/**
 * Allows for configuring a {@link SecurityBuilder}. All
 * {@link SecurityConfigurator} first have their {@link #init(SecurityBuilder)}
 * method invoked. After all {@link #init(SecurityBuilder)} methods have been
 * invoked, each {@link #configure(SecurityBuilder)} method is invoked.
 *
 * @author Rob Winch
 *
 * @param <O>
 *            The object being built by the {@link SecurityBuilder} B
 * @param <B>
 *            The {@link SecurityBuilder} that builds objects of type O. This is
 *            also the {@link SecurityBuilder} that is being configured.
 */
public interface SecurityConfigurator<O, B extends SecurityBuilder<O>> {
    /**
     * Initialize the {@link SecurityBuilder}. Here only shared state should be
     * created and modified, but not properties on the {@link SecurityBuilder}
     * used for building the object. This ensures that the
     * {@link #configure(SecurityBuilder)} method uses the correct shared
     * objects when building.
     *
     * @param builder
     * @throws Exception
     */
    void init(B builder) throws Exception;

    /**
     * Configure the {@link SecurityBuilder} by setting the necessary properties
     * on the {@link SecurityBuilder}.
     *
     * @param builder
     * @throws Exception
     */
    void configure(B builder) throws Exception;
}
