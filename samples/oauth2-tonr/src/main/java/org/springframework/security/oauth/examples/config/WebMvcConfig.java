package org.springframework.security.oauth.examples.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.support.ConversionServiceFactoryBean;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.converter.BufferedImageHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.springframework.security.oauth.examples.tonr.converter.AccessTokenRequestConverter;
import org.springframework.security.oauth.examples.tonr.impl.SparklrServiceImpl;
import org.springframework.security.oauth.examples.tonr.mvc.FacebookController;
import org.springframework.security.oauth.examples.tonr.mvc.SparklrController;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.web.accept.ContentNegotiationManagerFactoryBean;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.view.ContentNegotiatingViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.json.MappingJacksonJsonView;

@Configuration
@EnableWebMvc
@ImportResource("/WEB-INF/spring-servlet.xml")
//@Import(SecurityConfig.class)
public class WebMvcConfig extends WebMvcConfigurerAdapter {
    @Bean
    public PropertySourcesPlaceholderConfigurer myPropertySourcesPlaceholderConfigurer() {
        PropertySourcesPlaceholderConfigurer p = new PropertySourcesPlaceholderConfigurer();
        p.setLocation(new ClassPathResource("sparklr.properties"));
        return p;
    }

    @Bean
    public ContentNegotiatingViewResolver contentViewResolver() throws Exception {
        ContentNegotiatingViewResolver contentViewResolver = new ContentNegotiatingViewResolver();
        ContentNegotiationManagerFactoryBean contentNegotiationManager = new ContentNegotiationManagerFactoryBean();
        contentNegotiationManager.addMediaType("json", MediaType.APPLICATION_JSON);
        contentViewResolver.setContentNegotiationManager(contentNegotiationManager.getObject());
        contentViewResolver.setDefaultViews(Arrays.<View>asList(new MappingJacksonJsonView()));
        return contentViewResolver;
    }

    @Bean
    public ViewResolver viewResolver() {
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/jsp/");
        viewResolver.setSuffix(".jsp");
        return viewResolver;
    }

    @Override
    public void configureDefaultServletHandling(
            DefaultServletHandlerConfigurer configurer) {
        configurer.enable();
    }

    @Bean
    public SparklrController sparklrController(SparklrService sparklrService) {
        SparklrController controller = new SparklrController();
        controller.setSparklrService(sparklrService);
        return controller;
    }

    @Bean
    public FacebookController facebookController(@Qualifier("facebookRestTemplate") OAuth2RestTemplate facebookRestTemplate) {
        FacebookController controller = new FacebookController();
        controller.setFacebookRestTemplate(facebookRestTemplate);
        return controller;
    }

    @Bean
    public SparklrServiceImpl sparklrService(@Value("${sparklrPhotoListURL}") String sparklrPhotoListURL,
            @Value("${sparklrPhotoURLPattern}") String sparklrPhotoURLPattern,
            @Value("${sparklrTrustedMessageURL}") String sparklrTrustedMessageURL,
            @Qualifier("sparklrRestTemplate") OAuth2RestTemplate sparklrRestTemplate,
            @Qualifier("trustedClientRestTemplate") OAuth2RestTemplate trustedClientRestTemplate) {
        SparklrServiceImpl sparklrService = new SparklrServiceImpl();
        sparklrService.setSparklrPhotoListURL(sparklrPhotoListURL);
        sparklrService.setSparklrPhotoURLPattern(sparklrPhotoURLPattern);
        sparklrService.setSparklrTrustedMessageURL(sparklrTrustedMessageURL);
        sparklrService.setSparklrRestTemplate(sparklrRestTemplate);
        sparklrService.setTrustedClientRestTemplate(trustedClientRestTemplate);
        return sparklrService;
    }

    @Bean
    public ConversionServiceFactoryBean conversionService() {
        ConversionServiceFactoryBean conversionService = new ConversionServiceFactoryBean();
        conversionService.setConverters(Collections.singleton(new AccessTokenRequestConverter()));
        return conversionService;
    }

    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/resources/**").addResourceLocations("/resources/");
    }

    @Override
    public void configureMessageConverters(
            List<HttpMessageConverter<?>> converters) {
        converters.add(new BufferedImageHttpMessageConverter());
    }
}
