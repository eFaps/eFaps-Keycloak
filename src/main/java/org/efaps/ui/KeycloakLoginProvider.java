/*
 * Copyright 2003 - 2017 The eFaps Team
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

import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpSession;

import org.efaps.admin.user.Person;
import org.efaps.api.ui.ILoginProvider;
import org.efaps.db.Context;
import org.efaps.util.EFapsException;
import org.efaps.util.UUIDUtil;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore.SerializableKeycloakAccount;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Class KeycloakLoginProvider.
 */
public class KeycloakLoginProvider
    implements ILoginProvider
{

    /**
     * Logger for this class.
     */
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakLoginProvider.class);

    @Override
    public String login(final HttpSession _httpSession)
    {
        String ret = null;

        final SerializableKeycloakAccount account = (SerializableKeycloakAccount) _httpSession.getAttribute(
                        KeycloakAccount.class.getName());
        if (account != null) {
            try {
                if (Context.isTMActive()) {
                    Context.getThreadContext();
                } else {
                    Context.begin();
                }
                boolean ok = false;
                final String userName = account.getPrincipal().getName();
                final IDToken token = account.getKeycloakSecurityContext().getIdToken();
                final AccessToken atoken = account.getKeycloakSecurityContext().getToken();

                final Map<String, Object> otherClaims = token.getOtherClaims();

                try {
                    Person.reset(userName);
                    if (UUIDUtil.isUUID(userName)) {
                        ok = Person.get(UUID.fromString(userName)) != null;
                    } else {
                        ok = Person.get(userName) != null;
                    }
                } finally {
                    if (ok && Context.isTMActive()) {
                        Context.commit();
                    } else {
                        if (Context.isTMMarkedRollback()) {
                            LOG.error("transaction is marked to roll back");
                        } else {
                            LOG.error("transaction manager in undefined status");
                        }
                        Context.rollback();
                    }
                    if (ok) {
                        ret = userName;
                    }
                }
            } catch (final EFapsException e) {
                LOG.error("could not verify person", e);
            }
        }
        return ret;
    }
}
