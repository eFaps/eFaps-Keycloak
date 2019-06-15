/*
 * Copyright 2003 - 2019 The eFaps Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.efaps.ui.filter;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.keycloak.adapters.AuthenticatedActionsHandler;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.PreAuthActionsHandler;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore;
import org.keycloak.adapters.servlet.OIDCServletHttpFacade;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.UserSessionManagement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author The eFaps Team
 */
public class KeycloakFilter
    extends KeycloakOIDCFilter
{

    /**
     * Logging instance used in this class.
     */
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakFilter.class);

    @Override
    public void init(final FilterConfig _filterConfig)
        throws ServletException
    {
        super.init(_filterConfig);
    }

    @SuppressWarnings("checkstyle:returncount")
    @Override
    public void doFilter(final ServletRequest _req, final ServletResponse _res, final FilterChain _chain)
        throws IOException, ServletException
    {
        KeycloakFilter.LOG.debug("Keycloak OIDC Filter");
        final HttpServletRequest request = (HttpServletRequest) _req;
        final HttpServletResponse response = (HttpServletResponse) _res;

        final OIDCServletHttpFacade facade = new OIDCServletHttpFacade(request, response);
        final KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);
        if (deployment == null || !deployment.isConfigured()) {
            response.sendError(403);
            KeycloakFilter.LOG.error("deployment not configured");
            return;
        }

        final PreAuthActionsHandler preActions = new PreAuthActionsHandler(new UserSessionManagement()
        {

            @Override
            public void logoutAll()
            {
                if (KeycloakFilter.this.idMapper != null) {
                    KeycloakFilter.this.idMapper.clear();
                }
            }

            @Override
            public void logoutHttpSessions(final List<String> _ids)
            {
                KeycloakFilter.LOG.debug("**************** logoutHttpSessions");
                for (final String id : _ids) {
                    KeycloakFilter.LOG.debug("removed idMapper: " + id);
                    KeycloakFilter.this.idMapper.removeSession(id);
                }
            }
        }, deploymentContext, facade);

        if (preActions.handleRequest()) {
            return;
        }

        nodesRegistrationManagement.tryRegister(deployment);
        final OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(request, facade, 100000, deployment,
                        idMapper);
        tokenStore.checkCurrentToken();

        final FilterRequestAuthenticator authenticator = new FilterRequestAuthenticator(deployment, tokenStore, facade,
                        request, 8443);
        final AuthOutcome outcome = authenticator.authenticate();
        if (outcome == AuthOutcome.AUTHENTICATED) {
            KeycloakFilter.LOG.debug("AUTHENTICATED");
            if (facade.isEnded()) {
                return;
            }
            final AuthenticatedActionsHandler actions = new AuthenticatedActionsHandler(deployment, facade);
            if (actions.handledRequest()) {
                return;
            } else {
                final HttpServletRequestWrapper wrapper = tokenStore.buildWrapper();
                _chain.doFilter(wrapper, _res);
                return;
            }
        }
        if (request.getQueryString() != null) {
            KeycloakFilter.LOG.debug("Evaluating Query String");
            final boolean ajax = BooleanUtils.toBoolean(request.getHeader("Wicket-Ajax")) || BooleanUtils
                            .toBoolean(request.getParameter("wicket-ajax"));

            final String uri = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort()
                            + request.getContextPath();
            final StringBuilder html = new StringBuilder();
            if (ajax) {
                html.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                    .append("<ajax-response><evaluate>")
                    .append("\n/*<![CDATA[*/\n")
                    .append("  top.location = \"").append(StringEscapeUtils.escapeEcmaScript(uri)).append("\";")
                    .append("\n/*]]>*/\n")
                    .append("</evaluate></ajax-response>");
                KeycloakFilter.LOG.debug("Responding Ajax: {}", html);
            } else {
                html.append("<html> <head>")
                            .append("<script type=\"text/javascript\" >")
                            .append("function test4top() {\n")
                            .append("  if(top!=self) {\n")
                            .append("    top.location = \"").append(StringEscapeUtils.escapeEcmaScript(uri))
                                .append("\";")
                            .append("  }\n")
                            .append("}\n")
                            .append("</script>\n</head>")
                            .append("<body  onload=\"test4top()\"></body>")
                            .append("</html> ");
                KeycloakFilter.LOG.debug("Responding html: {}", html);
            }
            response.getOutputStream().print(html.toString());
            return;
        } else {
            final AuthChallenge challenge = authenticator.getChallenge();
            if (challenge != null) {
                KeycloakFilter.LOG.debug("challenge");
                challenge.challenge(facade);
                return;
            }
        }
        response.sendError(403);
    }
}
