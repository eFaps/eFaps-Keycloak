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

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;

import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.efaps.admin.EFapsSystemConfiguration;
import org.efaps.admin.user.Company;
import org.efaps.admin.user.JAASSystem;
import org.efaps.admin.user.Person;
import org.efaps.admin.user.Person.AttrName;
import org.efaps.admin.user.Role;
import org.efaps.api.ui.ILoginProvider;
import org.efaps.ci.CIAdmin;
import org.efaps.db.Context;
import org.efaps.db.InstanceQuery;
import org.efaps.db.QueryBuilder;
import org.efaps.util.EFapsException;
import org.efaps.util.UUIDUtil;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore.SerializableKeycloakAccount;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Class KeycloakLoginProvider.
 */
public class KeycloakLoginProvider
    implements ILoginProvider
{

    /** The rolekey. */
    public static final String ROLEKEY = "eFapsRoles";

    /** The Constant LANGKEY. */
    public static final String LANGKEY = "eFapsLanguage";

    /** The Constant LOCALEKEY. */
    public static final String LOCALEKEY = "eFapsLocale";

    /** The Constant TZKEY. */
    public static final String TZKEY = "eFapsTimeZone";

    /** The Constant COMPANIESKEY. */
    public static final String COMPANIESKEY = "eFapsCompanies";

    /** The Constant PERMITROLEUPDATE. */
    private static final String PERMITROLEUPDATE = "org.efaps.kernel.sso.PermitRoleUpdate";

    /** The Constant PERMITCOMPANYUPDATE. */
    private static final String PERMITCOMPANYUPDATE = "org.efaps.kernel.sso.PermitCompanyUpdate";

    /** The Constant PERMITATTRIBUTEUPDATE. */
    private static final String PERMITATTRIBUTEUPDATE = "org.efaps.kernel.sso.PermitAttributeUpdate";

    /** The Constant PERMITCREATEPERSON. */
    private static final String PERMITCREATEPERSON = "org.efaps.kernel.sso.PermitCreatePerson";

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
                try {
                    final IDToken token = account.getKeycloakSecurityContext().getIdToken();
                    if (validatePerson(userName, token)) {
                        syncAttributes(userName, token);
                        syncRoles(userName, token);
                        syncCompanies(userName, token);
                        Person.reset(userName);
                        ok = getPerson(userName) != null;
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

    /**
     * Validate if a person exists in the eFaps-Database.
     * If it does not exists and it is permitted via SytemConfiguration
     * will create a basic Person. Update of Attributes etc.
     * must be done on syncAttributes.
     *
     * @param _userName the user name
     * @throws EFapsException on error
     */
    private boolean validatePerson(final String _userName,
                                   final IDToken _token)
        throws EFapsException
    {
        final Person person = getPerson(_userName);
        boolean ret = false;
        if (person != null) {
            ret = true;
        } else if (EFapsSystemConfiguration.get().getAttributeValueAsBoolean(PERMITCREATEPERSON)) {
            final String userName = UUIDUtil.isUUID(_userName) ? _token.getPreferredUsername() : _userName;
            Person.createPerson(JAASSystem.getJAASSystem("eFaps"), userName, userName,
                            UUIDUtil.isUUID(_userName) ? _userName : null);
            ret = true;
        }
        return ret;
    }

    /**
     * Gets the person.
     *
     * @param _userName the user name
     * @return the person
     * @throws EFapsException the e faps exception
     */
    private Person getPerson(final String _userName)
        throws EFapsException
    {
        final Person person;
        if (UUIDUtil.isUUID(_userName)) {
            person = Person.get(UUID.fromString(_userName));
        } else {
            person = Person.get(_userName);
        }
        return person;
    }

    /**
     * Sync roles.
     *
     * @param _userName the user name
     * @param _token the token
     * @throws EFapsException the e faps exception
     */
    private void syncRoles(final String _userName,
                           final IDToken _token)
        throws EFapsException
    {
        if (EFapsSystemConfiguration.get().getAttributeValueAsBoolean(PERMITROLEUPDATE)) {
            final Map<String, Object> otherClaims = _token.getOtherClaims();
            if (otherClaims.containsKey(ROLEKEY)) {
                @SuppressWarnings("unchecked")
                final List<String> claims = (List<String>) otherClaims.get(ROLEKEY);
                final Person person = getPerson(_userName);
                if (person != null) {
                    final Set<Role> roles = new HashSet<>();
                    for (final String roleStr : claims) {
                        final Role role;
                        if (UUIDUtil.isUUID(roleStr)) {
                            role = Role.get(UUID.fromString(roleStr));
                        } else {
                            role = Role.get(roleStr);
                        }
                        if (role != null) {
                            roles.add(role);
                        }
                    }
                    final JAASSystem jaasSystem = JAASSystem.getJAASSystem("eFaps");
                    person.setRoles(jaasSystem, roles);
                }
            }
        }
    }

    /**
     * Sync companies.
     *
     * @param _userName the user name
     * @param _token the token
     * @throws EFapsException
     */
    private void syncCompanies(final String _userName, final IDToken _token)
        throws EFapsException
    {
        if (EFapsSystemConfiguration.get().getAttributeValueAsBoolean(PERMITCOMPANYUPDATE)) {
            final Map<String, Object> otherClaims = _token.getOtherClaims();
            if (otherClaims.containsKey(COMPANIESKEY)) {
                final String companiesStr = (String) otherClaims.get(COMPANIESKEY);
                final Person person = getPerson(_userName);
                if (person != null) {
                    final Set<Company> companies = new HashSet<>();
                    for (final String companyStr : StringUtils.split(companiesStr, "|")) {
                        final Company company;
                        if (UUIDUtil.isUUID(companyStr)) {
                            company = Company.get(UUID.fromString(companyStr));
                        } else {
                            company = Company.get(companyStr);
                        }
                        if (company != null) {
                            companies.add(company);
                        }
                    }
                    final JAASSystem jaasSystem = JAASSystem.getJAASSystem("eFaps");
                    person.setCompanies(jaasSystem, companies);
                }
            }
        }
    }

    /**
     * Sync attributes.
     *
     * @param _userName the user name
     * @param _token the token
     * @throws EFapsException the e faps exception
     */
    private void syncAttributes(final String _userName,
                                final IDToken _token)
        throws EFapsException
    {
        if (EFapsSystemConfiguration.get().getAttributeValueAsBoolean(PERMITATTRIBUTEUPDATE)) {
            final Person person = getPerson(_userName);
            if (person != null) {
                boolean update = false;
                if (!person.getFirstName().equals(_token.getGivenName())) {
                    person.updateAttrValue(AttrName.FIRSTNAME, _token.getGivenName());
                    update = true;
                }
                if (!person.getLastName().equals(_token.getFamilyName())) {
                    person.updateAttrValue(AttrName.LASTNAME, _token.getFamilyName());
                    update = true;
                }
                final Map<String, Object> otherClaims = _token.getOtherClaims();
                final String localeTag = (String) otherClaims.get(LOCALEKEY);
                if (StringUtils.isNotEmpty(localeTag) && !person.getLocale().toLanguageTag().equals(localeTag)
                                    && Locale.forLanguageTag(localeTag) != null) {
                    person.updateAttrValue(AttrName.LOCALE, localeTag);
                    update = true;
                }
                final String tzStr = (String) otherClaims.get(TZKEY);
                if (StringUtils.isNotEmpty(tzStr)) {
                    final TimeZone tz = TimeZone.getTimeZone(tzStr);
                    if (!person.getTimeZone().getID().equals(tzStr) && tz != null) {
                        person.updateAttrValue(AttrName.TIMZONE, tzStr);
                        update = true;
                    }
                }
                final String lang = (String) otherClaims.get(LANGKEY);
                if (StringUtils.isNotEmpty(lang) && !person.getLanguage().equals(lang)) {
                    final QueryBuilder queryBldr = new QueryBuilder(CIAdmin.Language);
                    queryBldr.addWhereAttrEqValue(CIAdmin.Language.Language, lang);
                    final InstanceQuery query = queryBldr.getQuery();
                    query.executeWithoutAccessCheck();
                    if (query.next()) {
                        person.updateAttrValue(AttrName.LANGUAGE, String.valueOf(query.getCurrentValue().getId()));
                        update = true;
                    }
                }
                if (update) {
                    person.commitAttrValuesInDB();
                }
            }
        }
    }
}
