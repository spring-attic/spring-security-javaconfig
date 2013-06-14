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

import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Adds a Filter that will generate a login page if one is not specified otherwise when using {@link WebSecurityConfigurerAdapter}.
 *
 * <p>
 * By default an {@link org.springframework.security.web.access.channel.InsecureChannelProcessor} and a {@link org.springframework.security.web.access.channel.SecureChannelProcessor} will be registered.
 * </p>
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are conditionally populated
 *
 * <ul>
 *     <li>{@link DefaultLoginPageGeneratingFilter} if the {@link FormLoginConfigurator} did not have a login page specified</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *isLogoutRequest
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 *     <li>{@link org.springframework.security.web.PortMapper} is used to create the default {@link org.springframework.security.web.access.channel.ChannelProcessor} instances</li>
 *     <li>{@link FormLoginConfigurator} is used to determine if the {@link DefaultLoginPageConfigurator} should be added and how to configure it.</li>
 * </ul>
 *
 * @see WebSecurityConfigurerAdapter
 *
 * @author Rob Winch
 * @since 3.2
 */
final class DefaultLoginPageConfigurator extends
        BaseHttpConfigurator {

    private DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = new DefaultLoginPageGeneratingFilter();
    DefaultLoginPageConfigurator(){}

    @Override
    public void init(HttpConfiguration http) throws Exception {
        FormLoginConfigurator formLogin = http.getConfigurator(FormLoginConfigurator.class);
        if(formLogin != null && !formLogin.isCustomLoginPage()) {

            loginPageGeneratingFilter.setFormLoginEnabled(true);
            loginPageGeneratingFilter.setUsernameParameter(formLogin.getUsernameParameter());
            loginPageGeneratingFilter.setPasswordParameter(formLogin.getPasswordParameter());
            loginPageGeneratingFilter.setLoginPageUrl(formLogin.getLoginPage());
            loginPageGeneratingFilter.setFailureUrl(formLogin.getFailureUrl());
            loginPageGeneratingFilter.setAuthenticationUrl(formLogin.getLoginProcessingUrl());
        }

        RememberMeConfigurator rememberme= http.getConfigurator(RememberMeConfigurator.class);
        if(rememberme != null) {
            loginPageGeneratingFilter.setRememberMeParameter(rememberme.getRememberMeParameter());
        }

        OpenIDLoginConfigurator openidLogin = http.getConfigurator(OpenIDLoginConfigurator.class);
        if(openidLogin != null && !openidLogin.isCustomLoginPage()) {
            loginPageGeneratingFilter.setOpenIdEnabled(true);
            loginPageGeneratingFilter.setOpenIDauthenticationUrl(openidLogin.getLoginProcessingUrl());
            if(formLogin == null) {
                loginPageGeneratingFilter.setLoginPageUrl(openidLogin.getLoginPage());
                loginPageGeneratingFilter.setFailureUrl(openidLogin.getFailureUrl());
            }
            loginPageGeneratingFilter.setOpenIDusernameParameter(OpenIDAuthenticationFilter.DEFAULT_CLAIMED_IDENTITY_FIELD);
        }

        LogoutConfigurator logout = http.getConfigurator(LogoutConfigurator.class);
        if(logout != null && !logout.isCustomLogoutSuccess()) {
            loginPageGeneratingFilter.setLogoutSuccessUrl(logout.getLogoutSuccessUrl());
        }
    }

    @Override
    public void configure(HttpConfiguration http) throws Exception {
        AuthenticationEntryPoint authenticationEntryPoint = null;
        ExceptionHandlingConfigurator exceptionConf = http.getConfigurator(ExceptionHandlingConfigurator.class);
        if(exceptionConf != null) {
            authenticationEntryPoint = exceptionConf.getAuthenticationEntryPoint();
        }

        if(loginPageGeneratingFilter.isEnabled() && authenticationEntryPoint == null) {
            loginPageGeneratingFilter = registerLifecycle(loginPageGeneratingFilter);
            http.addFilter(loginPageGeneratingFilter);
        }
    }


}