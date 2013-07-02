package org.springframework.security.config.annotation.web;
import org.junit.Test;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.web.FilterChainProxy;

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

/**
 * @author Rob Winch
 *
 */
public class SamplesWebSecurityXmlTests {

    @Test
    public void quickstart() {
        assertSecurityFilterChainLoads("classpath:quickstart.xml");
    }

    @Test
    public void samplesWebExampleA() {
        assertSecurityFilterChainLoads("classpath:samples-web-example-a.xml");
    }

    @Test
    public void samplesWebExampleB() {
        assertSecurityFilterChainLoads("classpath:samples-web-example-b.xml");
    }

    private void assertSecurityFilterChainLoads(String resource) {
        GenericXmlApplicationContext context = new GenericXmlApplicationContext(resource);
        try {
            context.getBean("springSecurityFilterChain",FilterChainProxy.class);
        } finally {
            context.close();
        }
    }
}
