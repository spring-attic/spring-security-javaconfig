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

import javax.sql.DataSource;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

/**
 * @author Rob Winch
 *
 */
public class PersistentRememberMeConfigurator extends RememberMeConfigurator {
    private PersistentTokenRepository tokenRepository = new InMemoryTokenRepositoryImpl();

    public RememberMeConfigurator tokenRepository(PersistentTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
        return this;
    }

    public RememberMeConfigurator dataSource(DataSource dataSource) {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        jdbcTokenRepository.afterPropertiesSet();
        return tokenRepository(jdbcTokenRepository);
    }

    @Override
    protected AbstractRememberMeServices createRememberMeServices(
            HttpConfiguration http, String key) {
        UserDetailsService userDetailsService = getUserDetailsService(http);
        return new PersistentTokenBasedRememberMeServices(key, userDetailsService, tokenRepository);
    }
}