package sandipchitale.actuatorsecurity;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.core.ApplicationFilterChain;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

@Configuration
public class DumpFiltersConfig {
    public static class DumpFilters extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain) throws ServletException, IOException {
            if (filterChain instanceof ApplicationFilterChain) {
                System.out.println();
                System.out.println("Begin Filters ============================");
                System.out.println("URL: " + request.getMethod() + " " + request.getRequestURI());
                ApplicationFilterChain applicationFilterChain = (ApplicationFilterChain) filterChain;
                try {
                    Field filters = applicationFilterChain.getClass().getDeclaredField("filters");
                    filters.setAccessible(true);
                    ApplicationFilterConfig[] filterConfigs = (ApplicationFilterConfig[]) filters
                            .get(applicationFilterChain);
                    boolean firstMatched = false;
                    for (ApplicationFilterConfig applicationFilterConfig : filterConfigs) {
                        if (applicationFilterConfig != null) {
                            System.out.println("Filter Name: " + applicationFilterConfig.getFilterName()
                                    + " FilterClass: " + applicationFilterConfig.getFilterClass());
                            if (applicationFilterConfig.getFilterName().equals("springSecurityFilterChain")) {
                                try {
                                    Method getFilter = applicationFilterConfig.getClass()
                                            .getDeclaredMethod("getFilter");
                                    getFilter.setAccessible(true);
                                    DelegatingFilterProxy delegatingFilterProxy = (DelegatingFilterProxy) getFilter
                                            .invoke(applicationFilterConfig);
                                    Field delegateField = DelegatingFilterProxy.class.getDeclaredField("delegate");
                                    delegateField.setAccessible(true);
                                    FilterChainProxy filterChainProxy = null;
                                    if (delegateField.get(delegatingFilterProxy) instanceof FilterChainProxy) {
                                        filterChainProxy = (FilterChainProxy) delegateField.get(delegatingFilterProxy);
                                    }
                                    if (delegateField.get(delegatingFilterProxy) instanceof DebugFilter debugFilter) {
                                        // DebugFilter debugFilter = (DebugFilter) delegateField.get(delegatingFilterProxy);
                                        System.out.println("\torg.springframework.security.web.debug.DebugFilter");
                                        filterChainProxy = debugFilter.getFilterChainProxy();
                                    }
                                    if (filterChainProxy != null) {
                                        List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
                                        System.out.println("Begin Filter Chains ============================");
                                        for (SecurityFilterChain securityFilterChain : filterChains) {
                                            DefaultSecurityFilterChain defaultSecurityFilterChain = (DefaultSecurityFilterChain) securityFilterChain;
                                            RequestMatcher requestMatcher = defaultSecurityFilterChain.getRequestMatcher();
                                            printRequestMatcher(requestMatcher, "\t");
                                            if (!firstMatched && defaultSecurityFilterChain.getRequestMatcher().matches(request)) {
                                                firstMatched = true;
                                                System.out.println("\t\t" + request.getMethod() + " " + request.getRequestURI() + " Matched");
                                            }
                                            List<Filter> securityFilters = securityFilterChain.getFilters();
                                            for (Filter securityFilter : securityFilters) {
                                                System.out.println("\t\t" + securityFilter);
                                            }
                                        }
                                        System.out.println("End Filter Chains ==============================");
                                    }
                                } catch (NoSuchMethodException | InvocationTargetException e) {
                                    System.out.println(e.getMessage());
                                }
                            }
                        }
                    }
                } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
                    System.out.println(e.getMessage());
                }
            }
            System.out.println("End Filters ==============================");
            filterChain.doFilter(request, response);
        }
    }

    // Recursive method to print RequestMatcher and its sub RequestMatchers
    private static void printRequestMatcher(RequestMatcher requestMatcher, String indent) {
        if (requestMatcher instanceof OrRequestMatcher orRequestMatcher) {
            System.out.println(indent + "Or");
            // OrRequestMatcher orRequestMatcher = (OrRequestMatcher) requestMatcher;
            Field requestMatchersField = ReflectionUtils.findField(OrRequestMatcher.class, "requestMatchers");
            ReflectionUtils.makeAccessible(requestMatchersField);
            List<RequestMatcher> requestMatchers =
                    (List<RequestMatcher>) ReflectionUtils.getField(requestMatchersField, requestMatcher);
            requestMatchers.forEach((RequestMatcher rm) -> {
                printRequestMatcher(rm, indent + "\t");
            });
        } else if (requestMatcher instanceof AndRequestMatcher andRequestMatcher) {
            System.out.println(indent + "And");
            // AndRequestMatcher andRequestMatcher = (AndRequestMatcher) requestMatcher;
            Field requestMatchersField = ReflectionUtils.findField(AndRequestMatcher.class, "requestMatchers");
            ReflectionUtils.makeAccessible(requestMatchersField);
            List<RequestMatcher> requestMatchers =
                    (List<RequestMatcher>) ReflectionUtils.getField(requestMatchersField, requestMatcher);
            requestMatchers.forEach((RequestMatcher rm) -> {
                printRequestMatcher(rm, indent + "\t");
            });
        } else if (requestMatcher instanceof NegatedRequestMatcher negatedRequestMatcher) {
            System.out.println(indent + "Not");
            // NegatedRequestMatcher negatedRequestMatcher = (NegatedRequestMatcher) requestMatcher;
            Field requestMatcherField = ReflectionUtils.findField(NegatedRequestMatcher.class, "requestMatcher");
            ReflectionUtils.makeAccessible(requestMatcherField);
            RequestMatcher rm = (RequestMatcher) ReflectionUtils.getField(requestMatcherField, requestMatcher);
            printRequestMatcher(rm, indent + "\t");
        } else {
            System.out.println(indent + requestMatcher);
            // Check if lambda - get the arg$1
            Field requestMatcherField = ReflectionUtils.findField(requestMatcher.getClass(), "arg$1");
            if (requestMatcherField != null) {
                ReflectionUtils.makeAccessible(requestMatcherField);
                Object o = ReflectionUtils.getField(requestMatcherField, requestMatcher);
                if (o != null) {
                    // Special case of OAuth2AuthorizationServerConfigurer.endpointsMatcher
                    Field endpointsMatcherField = ReflectionUtils.findField(o.getClass(), "endpointsMatcher");
                    if (endpointsMatcherField != null) {
                        ReflectionUtils.makeAccessible(endpointsMatcherField);
                        RequestMatcher rm = (RequestMatcher) ReflectionUtils.getField(endpointsMatcherField, o);
                        printRequestMatcher(rm, indent + "\t");
                    }
                }
            }
        }
    }

    @Bean
    FilterRegistrationBean<DumpFilters> filters() {
        FilterRegistrationBean<DumpFilters> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new DumpFilters());
        registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registrationBean;
    }
}