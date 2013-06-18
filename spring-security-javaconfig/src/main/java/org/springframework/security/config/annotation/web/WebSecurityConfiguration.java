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
package org.springframework.security.config.annotation.web;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * Uses a {@link WebSecurityBuilder} to create the {@link FilterChainProxy} that
 * performs the web based security for Spring Security. It then exports the
 * necessary beans. Customizations can be made to {@link WebSecurityBuilder} by
 * extending {@link WebSecurityConfigurerAdapter} and exposing it as a
 * {@link Configuration} or implementing {@link WebSecurityConfigurer} and
 * exposing it as a {@link Configuration}. This configuration is imported when
 * using {@link EnableWebSecurity}.
 *
 * @see EnableWebSecurity
 * @see WebSecurityBuilder
 *
 * @author Rob Winch
 * @since 3.2
 */
@Configuration
public class WebSecurityConfiguration {
    @Autowired
    private AutowireCapableBeanFactory beanFactory;

    private final WebSecurityBuilder webSecurityBuilder = new WebSecurityBuilder();

    private List<SecurityConfigurator<FilterChainProxy, WebSecurityBuilder>> webSecurityConfigurers;

    @Bean
    public LifecycleManager lifecycleManager() {
        return new AutowireBeanFactoryLifecycleManager(beanFactory);
    }

    @Bean
    public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
        return new DefaultWebSecurityExpressionHandler();
    }

    /**
     * Creates the Spring Security Filter Chain
     * @return
     * @throws Exception
     */
    @Bean(name="springSecurityFilterChain")
    public FilterChainProxy springSecurityFilterChain() throws Exception {
        boolean hasConfigurators = webSecurityConfigurers != null && !webSecurityConfigurers.isEmpty();
        if(!hasConfigurators) {
            throw new IllegalStateException("At least one non-null instance of "+ WebSecurityConfigurer.class.getSimpleName()+" must be exposed as a @Bean when using @EnableWebSecurity. Hint try extending "+ WebSecurityConfigurerAdapter.class.getSimpleName());
        }
        return webSecurityBuilder.build();
    }

    /**
     * Creates the {@link WebInvocationPrivilegeEvaluator} that is necessary for the JSP tag support.
     * @return the {@link WebInvocationPrivilegeEvaluator}
     * @throws Exception
     */
    @Bean
    public WebInvocationPrivilegeEvaluator privilegeEvaluator() throws Exception {
        FilterSecurityInterceptor securityInterceptor = webSecurityBuilder.getSecurityInterceptor();
        return securityInterceptor == null ? null : new DefaultWebInvocationPrivilegeEvaluator(securityInterceptor);
    }

    /**
     * Sets the {@code <SecurityConfigurator<FilterChainProxy, WebSecurityBuilder>} instances used to create the web configuration.
     *
     * @param webSecurityConfigurers the {@code <SecurityConfigurator<FilterChainProxy, WebSecurityBuilder>} instances used to create the web configuration
     * @throws Exception
     */
    @Autowired(required = false)
    public void setFilterChainProxySecurityConfigurator(
            List<SecurityConfigurator<FilterChainProxy, WebSecurityBuilder>> webSecurityConfigurers) throws Exception {
        Collections.sort(webSecurityConfigurers, AnnotationAwareOrderComparator.INSTANCE);

        Integer previousOrder = null;
        for(SecurityConfigurator<FilterChainProxy, WebSecurityBuilder> config : webSecurityConfigurers) {
            Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
            if(previousOrder != null && previousOrder.equals(order)) {
                throw new IllegalStateException("@Order on WebSecurityConfigurators must be unique. Order of " + order + " was already used, so it cannot be used on " + config + " too.");
            }
            previousOrder = order;
        }
        for(SecurityConfigurator<FilterChainProxy, WebSecurityBuilder> webSecurityConfigurer : webSecurityConfigurers) {
            webSecurityBuilder.apply(webSecurityConfigurer);
        }
        this.webSecurityConfigurers = webSecurityConfigurers;
    }


    /**
     * A custom verision of the Spring provided AnnotationAwareOrderComparator
     * that uses {@link AnnotationUtils#findAnnotation(Class, Class)} to look on
     * super class instances for the {@link Order} annotation.
     *
     * @author Rob Winch
     * @since 3.2
     */
    private static class AnnotationAwareOrderComparator extends OrderComparator {
        private static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();

        @Override
        protected int getOrder(Object obj) {
            return lookupOrder(obj);
        }

        private static int lookupOrder(Object obj) {
            if (obj instanceof Ordered) {
                return ((Ordered) obj).getOrder();
            }
            if (obj != null) {
                Class<?> clazz = (obj instanceof Class ? (Class<?>) obj : obj.getClass());
                Order order = AnnotationUtils.findAnnotation(clazz,Order.class);
                if (order != null) {
                    return order.value();
                }
            }
            return Ordered.LOWEST_PRECEDENCE;
        }
    }
}
