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
package org.springframework.security.config.annotation.web

import javax.servlet.ServletConfig
import javax.servlet.ServletContext

import org.springframework.beans.factory.BeanClassLoaderAware
import org.springframework.beans.factory.BeanFactoryAware
import org.springframework.beans.factory.BeanNameAware
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.context.ApplicationContextAware
import org.springframework.context.ApplicationEventPublisherAware
import org.springframework.context.EnvironmentAware
import org.springframework.context.MessageSourceAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockServletConfig
import org.springframework.mock.web.MockServletContext
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.SecurityBuilderPostProcessor;
import org.springframework.web.context.ServletConfigAware
import org.springframework.web.context.ServletContextAware
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext

/**
 *
 * @author Rob Winch
 */
class AutowireBeanFactoryLifecycleManagerTests extends BaseSpringSpec {

    def "Verify All Aware methods are invoked"() {
        setup:
            ApplicationContextAware contextAware = Mock(ApplicationContextAware)
            ApplicationEventPublisherAware publisher = Mock(ApplicationEventPublisherAware)
            BeanClassLoaderAware classloader = Mock(BeanClassLoaderAware)
            BeanFactoryAware beanFactory = Mock(BeanFactoryAware)
            EnvironmentAware environment = Mock(EnvironmentAware)
            MessageSourceAware messageSource = Mock(MessageSourceAware)
            ServletConfigAware servletConfig = Mock(ServletConfigAware)
            ServletContextAware servletContext = Mock(ServletContextAware)
            DisposableBean disposable = Mock(DisposableBean)

            context = new AnnotationConfigWebApplicationContext([servletConfig:new MockServletConfig(),servletContext:new MockServletContext()])
            context.register(Config)
            context.refresh()
            context.start()

            SecurityBuilderPostProcessor initializer = context.getBean(SecurityBuilderPostProcessor)
        when:
            initializer.postProcess(contextAware)
        then:
            1 * contextAware.setApplicationContext(!null)

        when:
            initializer.postProcess(publisher)
        then:
            1 * publisher.setApplicationEventPublisher(!null)

        when:
            initializer.postProcess(classloader)
        then:
            1 * classloader.setBeanClassLoader(!null)

        when:
            initializer.postProcess(beanFactory)
        then:
            1 * beanFactory.setBeanFactory(!null)

        when:
            initializer.postProcess(environment)
        then:
            1 * environment.setEnvironment(!null)

        when:
            initializer.postProcess(messageSource)
        then:
            1 * messageSource.setMessageSource(!null)

        when:
            initializer.postProcess(servletConfig)
        then:
            1 * servletConfig.setServletConfig(!null)

        when:
            initializer.postProcess(servletContext)
        then:
            1 * servletContext.setServletContext(!null)

        when:
            initializer.postProcess(disposable)
            context.close()
            context = null
        then:
            1 * disposable.destroy()
    }

    @Configuration
    static class Config {
        @Bean
        public SecurityBuilderPostProcessor lifecycleManager(AutowireCapableBeanFactory beanFactory) {
            return new AutowireBeanFactoryLifecycleManager(beanFactory);
        }
    }
}
