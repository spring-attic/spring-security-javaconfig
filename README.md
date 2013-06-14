Spring Security Java Config
======================

A project for Spring Security Java Configuration Support. We plan to release this jar in a number of milestones
to be able to iterate quickly. Additionally, this will allow users of Spring Security 3.1.x to use the
Java Configuration earlier and give more feedback. Eventually (targeting spring-security-config-3.2.0.RELEASE)
we will merge this code in with spring-security-config.

Quick Start - Hello Spring Security
==============

Below are the steps to get your application up and running quickly with Spring Security's Java Configuration. You can find this complete example in [samples/helloworld](samples/helloworld).

Building with Maven
-------------

You will need to ensure you have added the dependencies. The project is available in the [Spring Snapshot Repository](https://github.com/SpringSource/spring-framework/wiki/SpringSource-repository-FAQ).
In short, if you are using Maven ensure you have the following repository in your pom.xml:

```xml

    <repository>
        <id>spring-libs-snapshot</id>
        <name>Spring Snapshot Repository</name>
        <url>http://repo.springsource.org/snapshot</url>
        <releases>
            <enabled>false</enabled>
        </releases>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
    </repository>
```

You will then need to include the Spring Security Java Configuration jar.

```xml

    <dependencies>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-javaconfig</artifactId>
            <version>1.0.0.CI-SNAPSHOT</version>
        </dependency>
    </dependencies>
```

Hello World Web Configuration
----------------------

See [samples/helloworld/.../SecurityConfig.java](samples/helloworld/src/main/java/org/springframework/security/samples/config/SecurityConfig.java)

Create a `WebSecurityConfigurerAdapter` that is annotated with `@EnableWebSecurity`. You can find the simplest example below which does the following:

* Secures all URLs to require the user to be authenticated
* Creates a user with the username "user", password "password", and role of "ROLE_USER"
* Enables HTTP Basic and Form based authentication
* Spring Security will automatically render a login page for you

```java
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void registerAuthentication(AuthenticationRegistry registry) {
            registry
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }
    }
```

For reference, the JavaConfig above is similar to the following XML:

```xml
    <http use-expressions="true">
      <intercept-url pattern="/resources/**" access="permitAll"/>
      <intercept-url pattern="/**" access="authenticated"/>
      <logout
          logout-success-url="/login?logout"
          logout-url="/logout"
      <form-login
          authentication-failure-url="/login?error"
          login-page="/login" <!-- Except Spring Security renders the login page -->
          login-processing-url="/login" <!-- but only POST -->
          password-parameter="password"
          username-parameter="username"
      />
    </http>
    <authentication-manager>
      <authentication-provider>
          <user username="user" password="password" authorities="ROLE_USER"/>
        </user-service>
      </authentication-provider>
    </authentication-manager>
```

Sample WebApplicationInitializer's
----------------------

While using a web.xml is permissible, most users wanting to leverage Spring Security will want to use Java Configuration instead of a web.xml. If you wish to continue to use a web.xml use the same configuration for springSecurityFilterChain.

The first step is to ensure that you have initialized the ContextLoaderListener. Below is an example of how this is done when using Spring's WebApplicationInitializer interface. A complete example can be
in [MessageWebApplicationInitializer.java](samples/messages/src/main/java/org/springframework/security/samples/config/MessageWebApplicationInitializer.java) within the samples.

```java
    @Order(1)
    public class MessageWebApplicationInitializer extends
            AbstractAnnotationConfigDispatcherServletInitializer {

        @Override
        protected Class<?>[] getRootConfigClasses() {
            return new Class[] { RootConfiguration.class };
        }

        @Override
        protected Class<?>[] getServletConfigClasses() {
            return new Class[] { WebMvcConfiguration.class };
        }

        @Override
        protected String[] getServletMappings() {
            return new String[] { "/" };
        }

        @Override
        protected Filter[] getServletFilters() {
            return new Filter[] { new SiteMeshFilter() };
        }
    }
```

A few important points:

* The getRootConfigClasses is what initializes the ContextLoaderListener and should somehow include the Spring Security configuration. In our sample, RootConfiguration performs `@ComponentScan` that picks up our `@SecurityConfig`
* We add the @Order annotation to ensure that this WebApplicationInitializer happens first. This ensures that our SitemeshFilter is added AFTER our springSecurityFilterChain.
* SitemeshFilter is not required, but happens to be used in this application. If you do not use it do not worry about it
* WebMvcConfiguration is the Spring Web MVC configuration, if you are not using Spring Web MVC, consider using [AbstractContextLoaderInitializer](http://static.springsource.org/spring/docs/3.2.x/javadoc-api/org/springframework/web/context/AbstractContextLoaderInitializer.html)

Last you will want to add the springSecurityFilterChain. This can be done in many ways, but the easiest is to extend AbstractSecurityWebApplicationInitializer. In many instances, the following is all you will need to do:

```java
    public class MessageSecurityWebApplicationInitializer extends
            AbstractSecurityWebApplicationInitializer {
    }
```

Samples
======================

Below are a few additional samples to get you up and running quickly

Sample Web Security Spring Java Config
----------------------

See [SampleWebSecurityConfigurerAdapterTests.groovy](src/test/groovy/org/springframework/security/config/annotation/web/SampleWebSecurityConfigurerAdapterTests.groovy)

The following configuration

```java
    @Configuration
    @EnableWebSecurity
    public class SampleWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Override
        public void configure(WebSecurityConfiguration builder) throws Exception {
            builder
                .ignoring()
                    .antMatchers("/resources/**");
        }

        @Override
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .authorizeUrls()
                    .antMatchers("/signup","/about").permitAll()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    // You must render the login page now
                    .loginUrl("/login")
                    // set permitAll for all URLs associated with Form Login
                    .permitAll();
        }

        @Override
        protected void registerAuthentication(AuthenticationRegistry registry) {
            registry
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN");
        }
    }
```

is similar to the following XML configuration:

```xml
    <http security="none" pattern="/resources/**"/>
    <http use-expressions="true">
      <intercept-url pattern="/logout" access="permitAll"/>
      <intercept-url pattern="/login" access="permitAll"/>
      <intercept-url pattern="/signup" access="permitAll"/>
      <intercept-url pattern="/about" access="permitAll"/>
      <intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
      <logout
          logout-success-url="/login?logout"
          logout-url="/logout"
      <form-login
          authentication-failure-url="/login?error"
          login-page="/login"
          login-processing-url="/login" <!-- but only POST -->
          password-parameter="password"
          username-parameter="username"
      />
    </http>
    <authentication-manager>
      <authentication-provider>
        <user-service>
          <user username="user" password="password" authorities="ROLE_USER"/>
          <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
        </user-service>
      </authentication-provider>
    </authentication-manager>
```

Notice that Spring Security uses different defaults that will make your HTTP requests appear more RESTful. For example, the URL /login POST is used to
authenticate users. The URL /login GET is used to request the user for credentials (i.e. present a login form).

Sample Multi HTTP Web Configuration
----------------------

See [SampleWebSecurityConfigurerAdapterTests.groovy](src/test/groovy/org/springframework/security/config/annotation/web/SampleWebSecurityConfigurerAdapterTests.groovy)

The following configuration

```java
    @Configuration
    @EnableWebSecurity
    public class SampleMultiHttpSecurityConfig {
        @Bean
        public AuthenticationManager authenticationManager() {
            return new AuthenticationManagerBuilder()
                    .inMemoryAuthentication()
                        .withUser("user").password("password").roles("USER").and()
                        .withUser("admin").password("password").roles("USER", "ADMIN").and()
                        .and()
                    .build();
        }

        @Configuration
        @Order(1)
        public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .antMatcher("/api/**")
                    .authorizeUrls()
                        .antMatchers("/api/admin/**").hasRole("ADMIN")
                        .antMatchers("/api/**").hasRole("USER")
                        .and()
                    .httpBasic();
            }
        }

        @Configuration
        public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
            @Override
            public void configure(WebSecurityConfiguration builder) throws Exception {
                builder
                    .ignoring()
                        .antMatchers("/resources/**");
            }

            @Override
            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .authorizeUrls()
                        .antMatchers("/signup","/about").permitAll()
                        .anyRequest().hasRole("USER")
                        .and()
                    .formLogin()
                        .loginUrl("/login")
                        .permitAll();
            }
        }
    }
```

is similar to the following XML configuration:

```xml
    <http security="none" pattern="/resources/**"/>
    <http use-expressions="true" pattern="/api/**">
          <intercept-url pattern="/api/admin/**" access="hasRole('ROLE_ADMIN')"/>
          <intercept-url pattern="/api/**" access="hasRole('ROLE_USER')"/>
          <http-basic />
    </http>
    <http use-expressions="true">
      <intercept-url pattern="/logout" access="permitAll"/>
      <intercept-url pattern="/login" access="permitAll"/>
      <intercept-url pattern="/signup" access="permitAll"/>
      <intercept-url pattern="/about" access="permitAll"/>
      <intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
      <logout
          logout-success-url="/login?logout"
          logout-url="/logout"
      <form-login
          authentication-failure-url="/login?error"
          login-page="/login"
          login-processing-url="/login" <!-- but only POST -->
          password-parameter="password"
          username-parameter="username"
      />
    </http>
    <authentication-manager>
      <authentication-provider>
        <user-service>
          <user username="user" password="password" authorities="ROLE_USER"/>
          <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
        </user-service>
      </authentication-provider>
    </authentication-manager>
```

Sample Global Security Configuration
-------------

See [SampleEnableGlobalMethodSecurityTests.groovy](src/test/groovy/org/springframework/security/config/annotation/method/SampleEnableGlobalMethodSecurityTests.groovy)

Global configuration is quite simple. For example, the following Java Configuration:

```java
    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled=true)
    public class SampleWebSecurityConfig {
        @Bean
        public MethodSecurityService methodSecurityService() {
            return new MethodSecurityServiceImpl()
        }

        @Bean
        public AuthenticationManager authenticationManager() throws Exception {
            return new AuthenticationManagerBuilder()
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN").and()
                .build();
        }
    }
```

is the equivalent of:

```xml
    <global-method-security pre-post-annotations="enabled"/>
    <authentication-manager>
      <authentication-provider>
        <user-service>
          <user username="user" password="password" authorities="ROLE_USER"/>
          <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
        </user-service>
      </authentication-provider>
    </authentication-manager>
    <beans:bean id="methodSecuriytService" class="MethodSecurityServiceImpl"/>
```

There are additional attributes on `EnableGlobalMethodSecurity`, but in more advanced situations you may want to refer to another object. In order to do this,
override the `GlobalMethodSecurityConfiguration` class. For example, following Java configuration demonstrates how to override the MethodExpressionHandler to use
`CustomPermissionEvaluator`.

```java
    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled=true)
    public class CustomPermissionEvaluatorWebSecurityConfig extends GlobalMethodSecurityConfiguration {
        @Bean
        public MethodSecurityService methodSecurityService() {
            return new MethodSecurityServiceImpl()
        }

        @Override
        protected MethodSecurityExpressionHandler expressionHandler() {
            DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
            expressionHandler.setPermissionEvaluator(new CustomPermissionEvaluator());
            return expressionHandler;
        }

        @Override
        protected void registerAuthentication(AuthenticationRegistry registry)
            throws Exception {
            registry
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN");
        }
    }
```

The configuration above is the similar to the following XML configuration:

```xml
    <global-method-security pre-post-annotations="enabled">
        <expression-handler ref="expressionHandler"/>
    </global-method-security>
    <authentication-manager>
      <authentication-provider>
        <user-service>
          <user username="user" password="password" authorities="ROLE_USER"/>
          <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
        </user-service>
      </authentication-provider>
    </authentication-manager>
    <beans:bean id="methodSecuriytService" class="MethodSecurityServiceImpl"/>
    <beans:bean id="expressionHandler" class="CustomExpressionHandler"/>
```

Additional Samples
-------------

### Complete web applications

We include a number of complete [Sample Web Applications](./samples/) that use Spring Security Java Configuration.


### Mapping the XML namespace to JavaConfig

Also refer to the tests for further examples. You will notice a convention of Namespace<Security Element>Tests where <Security Element> is the Security Namespace
Element. For example, to learn how the <http> element and its attributes map to Spring Security Java Configuration look in the NamespaceHttpTests

FAQ
==============

Q: I'm getting getting a NoSuchBeanDefinitionException:

The full Exception is something similar (bean names can vary)

```
Caused by: org.springframework.beans.factory.NoSuchBeanDefinitionException: No bean named 'org.springframework.security.userDetailsService' is defined
    at org.springframework.beans.factory.support.DefaultListableBeanFactory.getBeanDefinition(DefaultListableBeanFactory.java:568)
    at org.springframework.beans.factory.support.AbstractBeanFactory.getMergedLocalBeanDefinition(AbstractBeanFactory.java:1099)
    at org.springframework.beans.factory.support.AbstractBeanFactory.doGetBean(AbstractBeanFactory.java:278)
    at org.springframework.beans.factory.support.AbstractBeanFactory.getBean(AbstractBeanFactory.java:194)
    at org.springframework.context.annotation.ConfigurationClassEnhancer$BeanMethodInterceptor.intercept(ConfigurationClassEnhancer.java:297)
    at org.test.demo.SecurityConfiguration$ApiConfiguration$$EnhancerByCGLIB$$e681011a.userDetailsServiceBean(<generated>)
    at org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter.http(WebSecurityConfigurerAdapter.java:66)
```

A: If you are get the error above or something similar, you should ensure you have updated to Spring Framework 3.2.3.RELEASE+ or 4.0.0.M1+ to avoid running into [SPR-10546](https://jira.springsource.org/browse/SPR-10546)

Contributing
==============
Before contributing or logging an issue please be sure to the issue does not already exist in this project's [issue tracking](https://github.com/SpringSource/spring-security-javaconfig/issues). If one does not exist, please create an issue.

If you see anything you'd like to change we encourage taking advantage of github's social coding features by making the change in a [fork of this repository](http://help.github.com/forking/) and sending a pull request.

Before we accept a non-trivial patch or pull request we will need you to sign the [contributor's agreement](https://support.springsource.com/spring_committer_signup). Signing the contributor's agreement does not grant anyone commit rights to the main repository, but it does mean that we can accept your contributions, and you will get an author credit if we do. Active contributors might be asked to join the core team, and given the ability to merge pull requests.

License
==============
The Spring Security Java Config project is available under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

