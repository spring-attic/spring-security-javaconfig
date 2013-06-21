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

import javax.servlet.Filter;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityConfigurer;

/**
 * Allows customization to the {@link WebSecurityBuilder}. In most instances
 * users will use {@link EnableWebSecurity} and a create {@link Configuration}
 * that extends {@link WebSecurityConfigurerAdapter} which will automatically be
 * applied to the {@link WebSecurityBuilder} by the {@link EnableWebSecurity}
 * annotation.
 *
 * @see WebSecurityConfigurerAdapter
 *
 * @author Rob Winch
 * @since 3.2
 */
public interface WebSecurityConfigurer extends SecurityConfigurer<Filter, WebSecurityBuilder> {

}
