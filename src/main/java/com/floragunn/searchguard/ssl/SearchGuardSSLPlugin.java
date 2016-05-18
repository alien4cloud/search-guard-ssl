/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.ssl;

import io.netty.handler.ssl.OpenSsl;
import io.netty.util.internal.PlatformDependent;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;

import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.collect.ImmutableList;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.http.HttpServerModule;
import org.elasticsearch.plugins.AbstractPlugin;
import org.elasticsearch.rest.RestModule;
import org.elasticsearch.transport.TransportModule;

import com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyHttpServerTransport;
import com.floragunn.searchguard.ssl.rest.SearchGuardSSLInfoAction;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLNettyTransport;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLTransportService;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public final class SearchGuardSSLPlugin extends AbstractPlugin {

    private final ESLogger log = Loggers.getLogger(this.getClass());
    static final String CLIENT_TYPE = "client.type";
    private final boolean client;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;
    private final Settings settings;

    public SearchGuardSSLPlugin(final Settings settings) {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        // initialize native netty open ssl libs

        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                PlatformDependent.hasUnsafe();
                OpenSsl.isAvailable();
                return null;
            }
        });

        this.settings = settings;
        client = !"node".equals(this.settings.get(SearchGuardSSLPlugin.CLIENT_TYPE));
        httpSSLEnabled = settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED,
                SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT);
        transportSSLEnabled = settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED,
                SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_DEFAULT);

        if (!httpSSLEnabled && !transportSSLEnabled) {
            log.error("SSL not activated for http and/or transport.");
            System.out.println("SSL not activated for http and/or transport.");
        }

    }

    @Override
    public void processModule(Module module) {
        if (!client && module instanceof RestModule) {
            ((RestModule) module).addRestAction(SearchGuardSSLInfoAction.class);
        }
        if (!client && httpSSLEnabled && module instanceof HttpServerModule) {
            ((HttpServerModule) module).setHttpServerTransport(SearchGuardSSLNettyHttpServerTransport.class, name());
        }
        if (transportSSLEnabled&& module instanceof TransportModule) {
            TransportModule transportModule = (TransportModule) module;
            transportModule.setTransport(SearchGuardSSLNettyTransport.class, name());

            if (!client && !searchGuardPluginAvailable()) {
                transportModule.setTransportService(SearchGuardSSLTransportService.class, name());
            }
        }
    }

    @Override
    public Collection<Module> modules(Settings settings) {
        return ImmutableList.<Module> of(new SearchGuardSSLModule(this.settings));
    }

    @Override
    public String description() {
        return "Search Guard SSL";
    }

    @Override
    public String name() {
        return "search-guard-ssl";
    }

    private boolean searchGuardPluginAvailable() {
        try {
            getClass().getClassLoader().loadClass("com.floragunn.searchguard.SearchGuardPlugin");
            return true;
        } catch (final ClassNotFoundException cnfe) {
            return false;
        }
    }
}
