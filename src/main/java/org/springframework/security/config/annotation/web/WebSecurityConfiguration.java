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
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.firewall.HttpFirewall;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
@Configuration
public class WebSecurityConfiguration extends AbstractConfiguredSecurityBuilder<FilterChainProxy, WebSecurityConfiguration> {
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
        Collections.sort(webSecurityConfigurers, new AnnotationAwareOrderComparator());

        Integer previousOrder = null;
        for(WebSecurityConfigurer config : webSecurityConfigurers) {
            Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
            if(previousOrder != null && previousOrder.equals(order)) {
                throw new IllegalStateException("@Order on WebSecurityConfigurators must be unique. Order of " + order + " was already used, so it cannot be used on " + config + " too.");
            }
            previousOrder = order;
        }
        for(SecurityConfigurator<FilterChainProxy, WebSecurityConfiguration> webSecurityConfigurer : webSecurityConfigurers) {
            apply(webSecurityConfigurer);
        }
        this.webSecurityConfigurers = webSecurityConfigurers;
    }

    public IgnoredRequestRegistry ignoring() {
        return springSecurityFilterChain.ignoring();
    }

    public WebSecurityConfiguration httpFirewall(HttpFirewall httpFirewall) {
        springSecurityFilterChain.httpFirewall(httpFirewall);
        return this;
    }

    SpringSecurityFilterChainBuilder springSecurityFilterChainBuilder() throws Exception {
        return springSecurityFilterChain;
    }



    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.AbstractSecurityBuilder#doBuild()
     */
    @Override
    protected FilterChainProxy performBuild() throws Exception {
        return springSecurityFilterChain.build();
    }

    @Override
    protected void beforeInit() {
        boolean hasConfigurators = webSecurityConfigurers != null && !webSecurityConfigurers.isEmpty();
        if(!hasConfigurators) {
            throw new IllegalStateException("At least one non-null instance of "+ WebSecurityConfigurer.class.getSimpleName()+" must be exposed as a @Bean when using @EnableWebSecurity. Hint try extending "+ WebSecurityConfigurerAdapter.class.getSimpleName());
        }
    }

    private static class AnnotationAwareOrderComparator extends OrderComparator {

        @Override
        protected int getOrder(Object obj) {
            return lookupOrder(obj);
        }

        private static int lookupOrder(Object obj) {
            if (obj instanceof Ordered) {
                int order = ((Ordered) obj).getOrder();
                return order;
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
