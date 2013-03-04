package org.springframework.security.samples.config;

import javax.servlet.Filter;

import org.springframework.security.samples.mvc.config.WebMvcConfiguration;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

import com.opensymphony.sitemesh.webapp.SiteMeshFilter;

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

    /**
     * NOTE: It is important to note that these Filter's are only invoked on the
     * {@link DispatcherServlet}. This means any resources not served by the
     * {@link DispatcherServlet} will not be protected. If you want to protect
     * all URLs instead, you can override
     * {@link #onStartup(javax.servlet.ServletContext)} and add the
     * {@link DelegatingFilterProxy} there.
     */
    @Override
    protected Filter[] getServletFilters() {
        DelegatingFilterProxy filterChainProxy = new DelegatingFilterProxy();
        filterChainProxy.setTargetBeanName("springSecurityFilterChain");
        return new Filter[] { filterChainProxy, new SiteMeshFilter() };
    }
}
