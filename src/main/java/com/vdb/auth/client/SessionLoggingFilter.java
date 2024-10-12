package com.vdb.auth.client;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class SessionLoggingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(SessionLoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Logging the session ID
        if (request.getSession(false) != null) {
            logger.info("Session ID: {}", request.getSession(false).getId());
        } else {
            logger.info("No session found.");
        }

        // Log all session attributes
        if (request.getSession(false) != null) {
            request.getSession(false).getAttributeNames().asIterator().forEachRemaining(attr -> {
                logger.info("Session attribute: {} = {}", attr, request.getSession(false).getAttribute(attr));
            });
        }

        filterChain.doFilter(request, response);
    }
}