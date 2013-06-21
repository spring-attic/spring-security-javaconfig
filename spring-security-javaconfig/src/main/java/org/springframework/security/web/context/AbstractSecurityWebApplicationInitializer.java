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

import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.AbstractContextLoaderInitializer;
import org.springframework.web.context.WebApplicationContext;
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

    private static final String SERVLET_CONTEXT_PREFIX = "org.springframework.web.servlet.FrameworkServlet.CONTEXT.";

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
        DelegatingFilterProxy springSecurityFilterChain = new DelegatingFilterProxy("springSecurityFilterChain");
        String contextAttribute = getWebApplicationContextAttribute();
        if(contextAttribute != null) {
            springSecurityFilterChain.setContextAttribute(contextAttribute);
        }
        Dynamic registration = servletContext.addFilter("springSecurityFilterChain", springSecurityFilterChain);
        registration.setAsyncSupported(isAsyncSecuritySupported());
        EnumSet<DispatcherType> dispatcherTypes = getSecurityDispatcherTypes();
        registration.addMappingForUrlPatterns(dispatcherTypes, false, "/*");
    }

    /**
     * Returns the {@link DelegatingFilterProxy#getContextAttribute()} or null
     * if the parent {@link ApplicationContext} should be used. The default
     * behavior is to use the parent {@link ApplicationContext}.
     *
     * <p>
     * If {@link #getDispatcherWebApplicationContextSuffix()} is non-null the
     * {@link WebApplicationContext} for the Dispatcher will be used. This means
     * the child {@link ApplicationContext} is used to look up the
     * springSecurityFilterChain bean.
     * </p>
     *
     * @return the {@link DelegatingFilterProxy#getContextAttribute()} or null
     * if the parent {@link ApplicationContext} should be used
     */
    protected String getWebApplicationContextAttribute() {
        String dispatcherServletName = getDispatcherWebApplicationContextSuffix();
        if(dispatcherServletName == null) {
            return null;
        }
        return SERVLET_CONTEXT_PREFIX + dispatcherServletName;
    }

    /**
     * Return the <servlet-name> to use the DispatcherServlet's
     * {@link WebApplicationContext} to find the {@link DelegatingFilterProxy}
     * or null to use the parent {@link ApplicationContext}.
     *
     * <p>
     * For example, if you are using AbstractDispatcherServletInitializer or
     * AbstractAnnotationConfigDispatcherServletInitializer and using the
     * provided Servlet name, you can return "dispatcher" from this method to
     * use the DispatcherServlet's {@link WebApplicationContext}.
     * </p>
     *
     * @return the <servlet-name> of the DispatcherServlet to use its
     *         {@link WebApplicationContext} or null (default) to use the parent
     *         {@link ApplicationContext}.
     */
    protected String getDispatcherWebApplicationContextSuffix() {
        return null;
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
