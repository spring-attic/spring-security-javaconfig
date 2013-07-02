Web Security Samples
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
        public void configure(WebSecurity web) throws Exception {
            web
                .ignoring()
                    .antMatchers("/resources/**");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
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
        protected void registerAuthentication(AuthenticationManagerBuilder auth) {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN");
        }
    }
```

is similar to the following XML configuration with the following exceptions:

* login-page is only processed for HTTP GET
* login-processing-url is only processed for HTTP POST

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
      />
      <form-login
          authentication-failure-url="/login?error"
          login-page="/login"
          login-processing-url="/login"
          password-parameter="password"
          username-parameter="username"
      />
    </http>
    <authentication-manager>
      <authentication-provider>
        <user-service>
          <user name="user" password="password" authorities="ROLE_USER"/>
          <user name="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
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
            protected void configure(HttpSecurity http) throws Exception {
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
            public void configure(WebSecurity web) throws Exception {
                web
                    .ignoring()
                        .antMatchers("/resources/**");
            }

            @Override
            protected void configure(HttpSecurity http) throws Exception {
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

is similar to the following XML configuration with the following exceptions:

* login-page is only processed for HTTP GET
* login-processing-url is only processed for HTTP POST


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
      />
      <form-login
          authentication-failure-url="/login?error"
          login-page="/login"
          login-processing-url="/login"
          password-parameter="password"
          username-parameter="username"
      />
    </http>
    <authentication-manager>
      <authentication-provider>
        <user-service>
          <user name="user" password="password" authorities="ROLE_USER"/>
          <user name="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
        </user-service>
      </authentication-provider>
    </authentication-manager>
```