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

package com.floragunn.searchguard.ssl.transport;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.netty.channel.Channel;
import org.elasticsearch.common.netty.handler.ssl.SslHandler;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.*;
import org.elasticsearch.transport.netty.NettyTransportChannel;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class SearchGuardSSLTransportService extends TransportService {

    @Inject
    public SearchGuardSSLTransportService(final Settings settings, final Transport transport, final ThreadPool threadPool) {
        super(settings, transport, threadPool);
    }

    @Override
    public void registerHandler(String action, TransportRequestHandler handler) {
        super.registerHandler(action, new Interceptor(handler, action));
    }

    private class Interceptor<Request extends TransportRequest> implements TransportRequestHandler<Request> {

        private final ESLogger log = Loggers.getLogger(this.getClass());
        private final TransportRequestHandler<Request> handler;
        private final String action;

        public Interceptor(final TransportRequestHandler<Request> handler, final String acion) {
            super();
            this.handler = handler;
            this.action = acion;
        }

        @Override
        public Request newInstance() {
            return handler.newInstance();
        }

        @Override
        public String executor() {
            return handler.executor();
        }

        @Override
        public boolean isForceExecution() {
            return handler.isForceExecution();
        }

        @Override
        public void messageReceived(final Request request, final TransportChannel transportChannel) throws Exception {

            NettyTransportChannel nettyChannel = null;

            if (transportChannel instanceof NettyTransportChannel) {
                nettyChannel = (NettyTransportChannel) transportChannel;
            }

            if (nettyChannel == null) {
                messageReceivedDecorate(request, handler, transportChannel);
                return;
            }

            try {
                final Channel channel = nettyChannel.getChannel();
                final SslHandler sslhandler = (SslHandler) channel.getPipeline().get("ssl_server");

                if (sslhandler == null) {
                    final String msg = "No ssl handler found (SG 11)";
                    log.error(msg);
                    final Exception exception = new ElasticsearchException(msg);
                    nettyChannel.sendResponse(exception);
                    throw exception;
                }

                X500Principal principal;

                final Certificate[] certs = sslhandler.getEngine().getSession().getPeerCertificates();

                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
                    addAdditionalContextValues(action, request, x509Certs);
                    principal = x509Certs[0].getSubjectX500Principal();
                    request.putInContext("_sg_ssl_transport_principal", principal == null ? null : principal.getName());
                    request.putInContext("_sg_ssl_transport_peer_certificates", x509Certs);
                    request.putInContext("_sg_ssl_transport_protocol", sslhandler.getEngine().getSession().getProtocol());
                    request.putInContext("_sg_ssl_transport_cipher", sslhandler.getEngine().getSession().getCipherSuite());
                    messageReceivedDecorate(request, handler, nettyChannel);
                } else {
                    final String msg = "No X509 transport client certificates found (SG 12)";
                    log.error(msg);
                    final Exception exception = new ElasticsearchException(msg);
                    nettyChannel.sendResponse(exception);
                    throw exception;
                }

            } catch (final SSLPeerUnverifiedException e) {
                log.error("Can not verify SSL peer (SG 13) due to {}", e, e);
                final Exception exception = ExceptionsHelper.convertToElastic(e);
                nettyChannel.sendResponse(exception);
                throw exception;
            } catch (final Exception e) {
                log.debug("Unexpected but unproblematic exception (SG 14) due to {}", e, e);
                //final Exception exception = ExceptionsHelper.convertToElastic(e);
                //nettyChannel.sendResponse(exception);
                throw e;
            }
        }

    }

    protected void addAdditionalContextValues(final String action, final TransportRequest request, final X509Certificate[] certs)
            throws Exception {
        // no-op
    }

    protected void messageReceivedDecorate(final TransportRequest request, final TransportRequestHandler handler, final TransportChannel transportChannel) throws Exception {
        handler.messageReceived(request, transportChannel);
    }
}
