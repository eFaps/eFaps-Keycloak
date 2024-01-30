/*
 * Copyright © 2003 - 2024 The eFaps Team (-)
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
 */
package org.efaps.ui.filter;

import javax.servlet.http.HttpServletRequest;

import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OAuthRequestAuthenticator;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AdapterSessionStore;
import org.keycloak.adapters.spi.HttpFacade;

public class FilterRequestAuthenticator
    extends org.keycloak.adapters.servlet.FilterRequestAuthenticator
{

    public FilterRequestAuthenticator(final KeycloakDeployment deployment,
                                      final AdapterTokenStore tokenStore,
                                      final OIDCHttpFacade facade,
                                      final HttpServletRequest request,
                                      final int sslRedirectPort)
    {
        super(deployment, tokenStore, facade, request, sslRedirectPort);
    }

    @Override
    protected OAuthRequestAuthenticator createOAuthAuthenticator()
    {
        return new StaticOAuthRequestAuthenticator(this, facade, deployment, sslRedirectPort, tokenStore);
    }

    public static class StaticOAuthRequestAuthenticator
        extends OAuthRequestAuthenticator
    {

        public StaticOAuthRequestAuthenticator(final RequestAuthenticator requestAuthenticator,
                                               final HttpFacade facade,
                                               final KeycloakDeployment deployment,
                                               final int sslRedirectPort,
                                               final AdapterSessionStore tokenStore)
        {
            super(requestAuthenticator, facade, deployment, sslRedirectPort, tokenStore);
        }

        @Override
        protected String getRequestUrl()
        {
            String redirect_uri = System.getenv("REDIRECT_URI");
            if (redirect_uri == null) {
                redirect_uri = super.getRequestUrl();
            }
            return redirect_uri;
        }
    }

}
