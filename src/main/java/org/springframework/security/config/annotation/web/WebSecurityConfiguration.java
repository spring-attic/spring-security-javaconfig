/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.config.annotation.web;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.annotation.AbstractConfiguredBuilder;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
@Configuration
public class WebSecurityConfiguration extends AbstractConfiguredBuilder<FilterChainProxy, WebSecurityConfiguration> {
    private final SpringSecurityFilterChainBuilder springSecurityFilterChain = new SpringSecurityFilterChainBuilder();

    private List<WebSecurityConfigurer> webSecurityConfigurers;

    @Bean
    public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
        return new DefaultWebSecurityExpressionHandler();
    }

    @Bean(name="springSecurityFilterChain")
    public FilterChainProxy springSecurityFilterChain() throws Exception {
        return build();
    }

    @Bean
    public WebInvocationPrivilegeEvaluator privilegeEvaluator() throws Exception {
        FilterSecurityInterceptor securityInterceptor = springSecurityFilterChainBuilder().securityInterceptor();
        return securityInterceptor == null ? null : new DefaultWebInvocationPrivilegeEvaluator(securityInterceptor);
    }

    @Autowired(required = false)
    public void setFilterChainProxySecurityConfigurator(
            List<WebSecurityConfigurer> webSecurityConfigurers) throws Exception {
        Collections.sort(webSecurityConfigurers,AnnotationAwareOrderComparator.INSTANCE);
        for(SecurityConfigurator<FilterChainProxy, WebSecurityConfiguration> webSecurityConfigurer : webSecurityConfigurers) {
            apply(webSecurityConfigurer);
        }
        this.webSecurityConfigurers = webSecurityConfigurers;
    }

    SpringSecurityFilterChainBuilder springSecurityFilterChainBuilder() throws Exception {
        return springSecurityFilterChain;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.AbstractSecurityBuilder#doBuild()
     */
    @Override
    protected FilterChainProxy doBuild() throws Exception {
        verifyConfigurators();
        init();
        configure();
        return springSecurityFilterChain.build();
    }

    private void verifyConfigurators() {
        boolean hasConfigurators = webSecurityConfigurers != null && !webSecurityConfigurers.isEmpty();
        if(!hasConfigurators) {
            throw new IllegalStateException("At least one non-null instance of "+ WebSecurityConfigurer.class.getSimpleName()+" must be exposed as a @Bean when using @EnableWebSecurity. Hint try extending "+ WebSecurityConfigurerAdapter.class.getSimpleName());
        }
    }

    private static class AnnotationAwareOrderComparator extends OrderComparator {

        /**
         * Shared default instance of AnnotationAwareOrderComparator.
         */
        public static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();


        @Override
        protected int getOrder(Object obj) {
            if (obj instanceof Ordered) {
                return ((Ordered) obj).getOrder();
            }
            if (obj != null) {
                Class<?> clazz = (obj instanceof Class ? (Class) obj : obj.getClass());
                Order order = AnnotationUtils.findAnnotation(clazz,Order.class);
                if (order != null) {
                    return order.value();
                }
            }
            return Ordered.LOWEST_PRECEDENCE;
        }


        /**
         * Sort the given List with a default AnnotationAwareOrderComparator.
         * <p>Optimized to skip sorting for lists with size 0 or 1,
         * in order to avoid unnecessary array extraction.
         * @param list the List to sort
         * @see java.util.Collections#sort(java.util.List, java.util.Comparator)
         */
        public static void sort(List<?> list) {
            if (list.size() > 1) {
                Collections.sort(list, INSTANCE);
            }
        }

        /**
         * Sort the given array with a default AnnotationAwareOrderComparator.
         * <p>Optimized to skip sorting for lists with size 0 or 1,
         * in order to avoid unnecessary array extraction.
         * @param array the array to sort
         * @see java.util.Arrays#sort(Object[], java.util.Comparator)
         */
        public static void sort(Object[] array) {
            if (array.length > 1) {
                Arrays.sort(array, INSTANCE);
            }
        }

    }
}
