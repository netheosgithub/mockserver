package org.mockserver.socket;

import com.google.common.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.net.ssl.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * @author jamesdbloom
 */
public class SSLFactory {

    public static final String KEY_STORE_SERVER_ALIAS = "serverAlias";
    public static final String KEY_STORE_CLIENT_ALIAS = "clientAlias";
    public static final String KEY_STORE_CA_ALIAS = "caAlias";
    public static final String KEY_STORE_PASSWORD = "changeit";
    public static final String KEY_STORE_FILENAME = "keystore.jks";
    private static final SSLFactory sslFactory = new SSLFactory();
    private static final Logger logger = LoggerFactory.getLogger(SSLFactory.class);
    private static final TrustManager DUMMY_TRUST_MANAGER = new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            logger.trace("Approving client certificate for: " + chain[0].getSubjectDN());
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            logger.trace("Approving server certificate for: " + chain[0].getSubjectDN());
        }
    };
    private KeyStore keystore;

    @VisibleForTesting
    SSLFactory() {

    }

    public static SSLFactory getInstance() {
        return sslFactory;
    }

    public SSLContext sslContext() {
        try {
            buildKeyStore();
            // ssl context
            SSLContext sslContext = getSSLContextInstance("TLS");
            sslContext.init(new KeyManager[]{new SSLKeyManager(KEY_STORE_SERVER_ALIAS, KEY_STORE_CLIENT_ALIAS)}, new TrustManager[]{DUMMY_TRUST_MANAGER}, null);
            return sslContext;
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize the SSLContext", e);
        }
    }

    public SSLSocket wrapSocket(Socket socket) throws Exception {
        // ssl socket factory
        SSLSocketFactory sslSocketFactory = sslContext().getSocketFactory();

        // ssl socket
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(socket, socket.getInetAddress().getHostAddress(), socket.getPort(), true);
        sslSocket.setUseClientMode(true);
        sslSocket.startHandshake();
        return sslSocket;
    }

    public KeyStore buildKeyStore() {
        if (keystore == null) {
            File keyStoreFile = new File(KEY_STORE_FILENAME);
            if (keyStoreFile.exists()) {
                loadKeyStore(keyStoreFile);
            } else {
                dynamicallyCreateKeyStore();
                saveKeyStore();
            }
        }
        return keystore;
    }

    @VisibleForTesting
    SSLContext getSSLContextInstance(String protocol) throws NoSuchAlgorithmException {
        return SSLContext.getInstance(protocol);
    }

    @VisibleForTesting
    KeyManagerFactory getKeyManagerFactoryInstance(String algorithm) throws NoSuchAlgorithmException {
        return KeyManagerFactory.getInstance(algorithm);
    }

    private void dynamicallyCreateKeyStore() {
        try {
            keystore = new KeyStoreFactory().generateCertificate(
                    KEY_STORE_SERVER_ALIAS,
                    KEY_STORE_CA_ALIAS,
                    KEY_STORE_PASSWORD.toCharArray(),
                    "localhost", null, null
            );
        } catch (Exception e) {
            throw new RuntimeException("Exception while building KeyStore dynamically", e);
        }
    }

    private void loadKeyStore(File keyStoreFile) {
        try {
            FileInputStream fileInputStream = null;
            try {
                fileInputStream = new FileInputStream(KEY_STORE_FILENAME);
                logger.trace("Loading key store from file [" + keyStoreFile + "]");
                keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(fileInputStream, KEY_STORE_PASSWORD.toCharArray());
            } finally {
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Exception while loading KeyStore from " + keyStoreFile.getAbsolutePath(), e);
        }
    }

    private void saveKeyStore() {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            keystore.store(bout, KEY_STORE_PASSWORD.toCharArray());
            File keyStoreFile = new File(KEY_STORE_FILENAME);
            logger.trace("Saving key store to file [" + keyStoreFile + "]");
            FileOutputStream fileOutputStream = null;
            try {
                fileOutputStream = new FileOutputStream(keyStoreFile);
                fileOutputStream.write(bout.toByteArray());
            } finally {
                if (fileOutputStream != null) {
                    fileOutputStream.close();
                }
            }
            keyStoreFile.deleteOnExit();
        } catch (Exception e) {
            throw new RuntimeException("Exception while saving KeyStore", e);
        }
    }

    public static SSLEngine createClientSSLEngine() {
        SSLEngine engine = SSLFactory.getInstance().sslContext().createSSLEngine();
        engine.setUseClientMode(true);
        return engine;
    }

    public static SSLEngine createServerSSLEngine() {
        SSLEngine engine = SSLFactory.getInstance().sslContext().createSSLEngine();
        engine.setUseClientMode(false);
        return engine;
    }

    final class SSLKeyManager
            extends X509ExtendedKeyManager {

        private final String serverAlias;
        private final String clientAlias;

        public SSLKeyManager(String serverAlias, String clientAlias) {
            this.serverAlias = serverAlias;
            this.clientAlias = clientAlias;
        }

        @Override
        public String chooseEngineClientAlias(String[] strings, Principal[] prncpls, SSLEngine ssle) {
            return clientAlias;
        }

        @Override
        public String chooseEngineServerAlias(String string, Principal[] prncpls, SSLEngine ssle) {
            return serverAlias;
        }

        @Override
        public String chooseClientAlias(final String[] keyType, final Principal[] issuers, final Socket socket) {
            return clientAlias;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            try {
                Certificate[] certs = keystore.getCertificateChain(alias);
                if (certs == null) {
                    return null;
                }
                X509Certificate[] x509Certs = new X509Certificate[certs.length];
                for (int i = 0; i < certs.length; i++) {
                    x509Certs[i] = (X509Certificate) certs[i];
                }
                logger.trace("{} certificates found for alias {}", x509Certs.length, alias);
                return x509Certs;
            } catch (Exception ex) {
                throw new UnsupportedOperationException("Error getting certificate chain", ex);
            }
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            try {
                PrivateKey privKey = (PrivateKey) keystore.getKey(alias, KEY_STORE_PASSWORD.toCharArray());
                logger.trace("Private key ({}) -> {}", alias, privKey);
                return privKey;
            } catch (Exception ex) {
                throw new UnsupportedOperationException("Error getting private key", ex);
            }
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[]{
                clientAlias
            };
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return new String[]{
                serverAlias
            };
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return serverAlias;
        }

    }

}
