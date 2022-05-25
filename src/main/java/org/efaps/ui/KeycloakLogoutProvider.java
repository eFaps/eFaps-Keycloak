/*
 * Copyright 2003 - 2022 The eFaps Team
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
package org.efaps.ui;

import java.util.UUID;

import javax.servlet.http.HttpSession;

import org.efaps.admin.common.SystemConfiguration;
import org.efaps.api.ui.ILogoutProvider;
import org.efaps.util.EFapsException;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore.SerializableKeycloakAccount;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeycloakLogoutProvider
    implements ILogoutProvider
{

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakLogoutProvider.class);

    @Override
    public String logoutUrl(final HttpSession _httpSession)
    {
        final SerializableKeycloakAccount account = (SerializableKeycloakAccount) _httpSession.getAttribute(
                        KeycloakAccount.class.getName());
        final var idTokenString = account.getKeycloakSecurityContext().getIdTokenString();
        final var deployment = account.getKeycloakSecurityContext().getDeployment();

        final var logoutUrl = deployment.getLogoutUrl();
        logoutUrl.replaceQueryParam("id_token_hint", idTokenString);

        try {
            // WebApp-Configuration
            final var sysconf = SystemConfiguration.get(UUID.fromString("50a65460-2d08-4ea8-b801-37594e93dad5"));
            final var redirectUri = sysconf.getAttributeValue("org.efaps.webapp.PostLogoutRedirectUri");
            if (redirectUri != null) {
                logoutUrl.replaceQueryParam("post_logout_redirect_uri", redirectUri);
            }
        } catch (final EFapsException e) {
            LOG.error("Catched", e);
        }
        return logoutUrl.buildAsString();
    }
}
