/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.config;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import loophole.mvc.base.TemplateServlet;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ITemplateResolver;
import org.thymeleaf.templateresolver.WebApplicationTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

@WebListener
public class TemplateConfig implements ServletContextListener {

    private static final String TEMPLATE_ENGINE = "com.thymeleafexamples.thymeleaf3.TemplateEngineInstance";

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        TemplateEngine engine = templateEngine(sce.getServletContext());
        sce.getServletContext().setAttribute(TEMPLATE_ENGINE, engine);
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
    }

    private TemplateEngine templateEngine(ServletContext servletContext) {
        TemplateEngine engine = new TemplateEngine();
        engine.setTemplateResolver(templateResolver(servletContext));
        return engine;
    }

    private ITemplateResolver templateResolver(ServletContext servletContext) {
        JakartaServletWebApplication webApp = JakartaServletWebApplication.buildApplication(servletContext);
        WebApplicationTemplateResolver resolver = new WebApplicationTemplateResolver(webApp);
        resolver.setPrefix("/");
        resolver.setSuffix(TemplateServlet.VIEW_EXT);
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCacheable(true);
        resolver.setCacheTTLMs(60000L);
        resolver.setCharacterEncoding("UTF-8");
        return resolver;
    }

    public static TemplateEngine getTemplateEngine(ServletContext context) {
        return (TemplateEngine) context.getAttribute(TEMPLATE_ENGINE);
    }
}