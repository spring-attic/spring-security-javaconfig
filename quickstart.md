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
    @Configuration
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth) {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }
    }
```

For reference, the JavaConfig above is similar to the following XML with a few exceptions:

* login-page, logout-success-url, and authentication-failure-url are rendered by Spring Security
* login-page is only processed for HTTP GET
* login-processing-url is only processed for HTTP POST

```xml
    <http use-expressions="true">
      <intercept-url pattern="/**" access="authenticated"/>
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
