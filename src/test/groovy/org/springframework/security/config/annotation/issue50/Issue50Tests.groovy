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
package org.springframework.security.config.annotation.issue50;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.issue50.domain.User;
import org.springframework.security.config.annotation.issue50.repo.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import spock.lang.Specification;

/**
 * @author Rob Winch
 *
 */
@ContextConfiguration(classes=[ApplicationConfig.class,SecurityConfig.class])
@Transactional
class Issue50Tests extends Specification {
    @Autowired
    private FilterChainProxy springSecurityFilterChain
    @Autowired
    private AuthenticationManager authenticationManager
    @Autowired
    private UserRepository userRepo

    public void configurationLoadsWithNoErrors() {
        when:
        "Configuration loads"
        then:
        noExceptionThrown()
    }

    public void authenticationUserNotFound() {
        when:
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("test", "password"))
        then:
        thrown(UsernameNotFoundException)
    }

    public void authenticationBadCredentials() {
        when:
        User user = new User(username:"test",password:"password")
        userRepo.save(user)
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.username , "invalid"))
        then:
        thrown(BadCredentialsException)
    }

    public void authenticationSuccess() {
        when:
        User user = new User(username:"test",password:"password")
        userRepo.save(user)
        Authentication result = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.username , user.password))
        then:
        result.principal == user.username
    }
}
