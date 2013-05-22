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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class PortMapperConfigurator extends SecurityConfiguratorAdapter<DefaultSecurityFilterChain,HttpConfiguration> {
    private PortMapper portMapper;
    private Map<String, String> httpsPortMappings = new HashMap<String,String>();

    public PortMapperConfigurator portMapper(PortMapper portMapper) {
        this.portMapper = portMapper;
        return this;
    }

    public HttpPortMapping http(int httpPort) {
        return new HttpsPortMapping(httpPort);
    }

    @Override
    public void init(HttpConfiguration http) throws Exception {
        http.setSharedObject(PortMapper.class, getPortMapper());
    }

    /**
     * @return
     */
    private PortMapper getPortMapper() {
        if(portMapper == null) {
            PortMapperImpl portMapper = new PortMapperImpl();
            portMapper.setPortMappings(httpsPortMappings);
            this.portMapper = portMapper;
        }
        return portMapper;
    }


    public abstract static class HttpPortMapping {
        abstract PortMapperConfigurator mapsTo(int httpsPort);

        private HttpPortMapping(){}
    }

    public class HttpsPortMapping extends HttpPortMapping {
        private int httpPort;

        private HttpsPortMapping(int httpPort) {
            this.httpPort = httpPort;
        }

        @Override
        PortMapperConfigurator mapsTo(int httpsPort) {
            httpsPortMappings.put(String.valueOf(httpPort), String.valueOf(httpsPort));
            return PortMapperConfigurator.this;
        }

    }
}
