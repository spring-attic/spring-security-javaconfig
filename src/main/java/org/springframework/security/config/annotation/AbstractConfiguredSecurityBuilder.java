/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation;

import java.util.Collection;
import java.util.LinkedHashMap;

import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * A base {@link SecurityBuilder} that allows {@link SecurityConfigurator} to be
 * applied to it. This makes modifying the {@link SecurityBuilder} a strategy
 * that can be customized and broken up into a number of
 * {@link SecurityConfigurator} objects that have more specific goals than that
 * of the {@link SecurityBuilder}.
 *
 * For example, a {@link SecurityBuilder} may build an
 * {@link DelegatingFilterProxy}, but a {@link SecurityConfigurator} might
 * populate the {@link SecurityBuilder} with the filters necessary for session
 * management, form based login, authorization, etc.
 *
 * @author Rob Winch
 *
 * @param <T>
 *            The object that this builder returns
 * @param <B>
 *            The type of this builder (that is returned by the base class)
 *
 * @see SpringSecurityFilterChainBuilder
 *
 *
 */
public abstract class AbstractConfiguredSecurityBuilder<T, B extends SecurityBuilder<T>> extends AbstractSecurityBuilder<T> {

    private final LinkedHashMap<Class<? extends SecurityConfigurator<T, B>>, SecurityConfigurator<T, B>> configurators = new LinkedHashMap<Class<? extends SecurityConfigurator<T, B>>, SecurityConfigurator<T, B>>();

    /**
     * Applies a {@link SecurityConfigurator} to this {@link SecurityBuilder}. Typical usage might look like:
     *
     * <code>
     * builder
     *     .apply(new DemoSecurityConfigurator())
     *         .
     *
     * @param configurer
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public <C extends SecurityConfiguratorAdapter<T, B>> C apply(C configurer)
            throws Exception {
        if(isBuildingOrBuilt()) {
            throw new IllegalStateException("Cannot apply "+configurer+" to already built object");
        }
        configurer.setBuilder((B) this);
        return (C) apply((SecurityConfigurator<T, B>)configurer);
    }

    @SuppressWarnings("unchecked")
    public <C extends SecurityConfigurator<T, B>> C apply(C configurer)
            throws Exception {
        if(isBuildingOrBuilt()) {
            throw new IllegalStateException("Cannot apply "+configurer+" to already built object");
        }
        Class<? extends SecurityConfigurator<T, B>> clazz = (Class<? extends SecurityConfigurator<T, B>>) configurer
                .getClass();
        this.configurators.put(clazz, configurer);
        return configurer;
    }

    @SuppressWarnings("unchecked")
    protected <C extends SecurityConfigurator<T, B>> C getConfigurator(
            Class<C> clazz) {
        return (C) configurators.get(clazz);
    }

    public <C extends SecurityConfigurator<T,B>> C removeConfigurator(Class<C> clazz) {
        return (C) configurators.remove(clazz);
    }

    private void init() throws Exception {
        Collection<SecurityConfigurator<T,B>> configurators = getConfigurators();

        for(SecurityConfigurator<T,B> configurer : configurators ) {
            configurer.init((B) this);
        }
    }

    @Override
    protected final T doBuild() throws Exception {
        beforeInit();

        init();

        beforeConfigure();

        configure();

        return performBuild();
    }

    /**
     *
     */
    protected void beforeInit() throws Exception {
    }

    protected void beforeConfigure() throws Exception {
    }

    /**
     * @return
     */
    protected abstract T performBuild() throws Exception;

    private void configure() throws Exception {
        Collection<SecurityConfigurator<T,B>> configurators = getConfigurators();

        for(SecurityConfigurator<T,B> configurer : configurators ) {
            configurer.configure((B) this);
        }
    }

    private Collection<SecurityConfigurator<T, B>> getConfigurators() {
        return this.configurators.values();
    }
}