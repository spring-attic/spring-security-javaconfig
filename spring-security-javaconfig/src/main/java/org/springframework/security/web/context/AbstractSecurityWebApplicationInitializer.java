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
package org.springframework.security.web.context;

import java.util.EnumSet;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterRegistration.Dynamic;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.AbstractContextLoaderInitializer;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * Registers the {@link DelegatingFilterProxy} to use the
 * springSecurityFilterChain before any other registered {@link Filter}. This
 * class is typically used in addition to a subclass of
 * {@link AbstractContextLoaderInitializer}.
 *
 * <p>
 * By default the {@link DelegatingFilterProxy} is registered without support,
 * but can be enabled by overriding {@link #isAsyncSecuritySupported()} and
 * {@link #getSecurityDispatcherTypes()}.
 * </p>
 *
 * <p>
 * Additional configuration before and after the springSecurityFilterChain can
 * be added by overriding
 * {@link #beforeSpringSecurityFilterChain(ServletContext)} and
 * {@link #afterSpringSecurityFilterChain(ServletContext)}.
 * </p>
 *
 *
 * <h2>Caveats</h2>
 * <p>
 * Subclasses of AbstractDispatcherServletInitializer will register their
 * filters before any other {@link Filter}. This means that you will typically
 * want to ensure subclasses of AbstractDispatcherServletInitializer are invoked
 * first. This can be done by ensuring the {@link Order} or {@link Ordered} of
 * AbstractDispatcherServletInitializer are sooner than subclasses of
 * {@link AbstractSecurityWebApplicationInitializer}.
 * </p>
 *
 * @author Rob Winch
 */
public abstract class AbstractSecurityWebApplicationInitializer implements WebApplicationInitializer {

    /* (non-Javadoc)
     * @see org.springframework.web.WebApplicationInitializer#onStartup(javax.servlet.ServletContext)
     */
    @Override
    public final void onStartup(ServletContext servletContext)
            throws ServletException {
        beforeSpringSecurityFilterChain(servletContext);
        registerSpringSecurityFilterChain(servletContext);
        afterSpringSecurityFilterChain(servletContext);
    }

    /**
     * Invoked before the springSecurityFilterChain is added.
     * @param servletContext the {@link ServletContext}
     */
    protected void beforeSpringSecurityFilterChain(ServletContext servletContext) {

    }

    /**
     * Registers the springSecurityFilterChain
     * @param servletContext the {@link ServletContext}
     */
    private void registerSpringSecurityFilterChain(ServletContext servletContext) {
        Dynamic registration = servletContext.addFilter("springSecurityFilterChain", new DelegatingFilterProxy("springSecurityFilterChain"));
        registration.setAsyncSupported(isAsyncSecuritySupported());
        EnumSet<DispatcherType> dispatcherTypes = getSecurityDispatcherTypes();
        registration.addMappingForUrlPatterns(dispatcherTypes, false, "/*");
    }

    /**
     * Invoked after the springSecurityFilterChain is added.
     * @param servletContext the {@link ServletContext}
     */
    protected void afterSpringSecurityFilterChain(ServletContext servletContext) {

    }

    /**
     * Get the {@link DispatcherType} for the springSecurityFilterChain.
     * @return
     */
    protected EnumSet<DispatcherType> getSecurityDispatcherTypes() {
        return EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR);
    }

    /**
     * Determine if the springSecurityFilterChain should be marked as supporting
     * asynch.
     */
    private boolean isAsyncSecuritySupported() {
        return true;
    }

}
