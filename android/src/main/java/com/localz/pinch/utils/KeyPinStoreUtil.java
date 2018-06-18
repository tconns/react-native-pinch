package com.localz.pinch.utils;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class KeyPinStoreUtil {

    private static HashMap<String[], KeyPinStoreUtil> instances = new HashMap<>();
    private SSLContext sslContext = SSLContext.getInstance("TLS");
    private static String SSL_KEY = "";
    public static synchronized KeyPinStoreUtil getInstance(String[] filenames, String ssl_key) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        if (filenames != null && instances.get(filenames) == null) {
            instances.put(filenames, new KeyPinStoreUtil(filenames,ssl_key));
        }
        return instances.get(filenames);

    }

    private KeyPinStoreUtil(String[] filenames,String ssl_key) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        SSL_KEY= ssl_key;
        // Create a KeyStore for our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
//        String ssl_key ="-----BEGIN CERTIFICATE-----\n" +
//                "MIIDvDCCAqQCCQDZ1O99bT8pnjANBgkqhkiG9w0BAQUFADCBnzELMAkGA1UEBhMC\n" +
//                "Vk4xDzANBgNVBAgMBkhhIE5vaTEPMA0GA1UEBwwGSGEgTm9pMTgwNgYDVQQKDC9D\n" +
//                "QVBJVEFMIENPTU1VTklDQVRJT04gTUVESUEgSk9JTlQgU1RPQ0sgQ09NUEFOWTEW\n" +
//                "MBQGA1UECwwNSVQgRGVwYXJ0bWVudDEcMBoGA1UEAwwTZ2F0ZWFwcG90dC5ndmll\n" +
//                "dC52bjAeFw0xODA2MDgwMzAxMzdaFw0yODA2MDUwMzAxMzdaMIGfMQswCQYDVQQG\n" +
//                "EwJWTjEPMA0GA1UECAwGSGEgTm9pMQ8wDQYDVQQHDAZIYSBOb2kxODA2BgNVBAoM\n" +
//                "L0NBUElUQUwgQ09NTVVOSUNBVElPTiBNRURJQSBKT0lOVCBTVE9DSyBDT01QQU5Z\n" +
//                "MRYwFAYDVQQLDA1JVCBEZXBhcnRtZW50MRwwGgYDVQQDDBNnYXRlYXBwb3R0Lmd2\n" +
//                "aWV0LnZuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApJICtSScntq8\n" +
//                "lC/C1wh53vPbX+vuZ6IT5yfkxF500C561jcynQQ/8sTiAW0eXI2/9b3VaK9Nvek9\n" +
//                "sGBdAPhIDOQJQvwwK+kL8C7ZUBEJ12z8JADeybQ9h4v1Hb1h/jv12+cBYZuJIgqD\n" +
//                "fLqTDflu8t4XG3UDaBWbl2kOscjX0+BLY4tO/lnYVVTv3OfAlRobX/2UpyqiWgFP\n" +
//                "7sy/ylczYlda1ZUtc7ELoECdKqpkZ/VzaRKdEIhRrHJ5/qBC7BmxNDFEBvf/c4V2\n" +
//                "n2jRBRtMIVe13k+Tlki7jm2WLF/5ScGbcEydeVsyS75kNF6efpbOaep518RG24FJ\n" +
//                "iv2d1Dmk4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAI/PDSfremcrHOGWPJTJ5y\n" +
//                "FJ661p7mTU7fVoHSzC3+Cq3RaJ6OswMZI+IIbMNzrxCg+kkUVslNphPOm6Y5oFdF\n" +
//                "sr+SGmxvc05JlJQcBbMeXBsOgdYa4pgsUzOLzpd+Yrf50gD2cBh63c8u5Pe7JJzZ\n" +
//                "w6NNVqEZrrQ0cgAJUWY2+IomRp4Wm5M/ImClllxS+uVm3yM0xfiAM/m1Ax23Gjb6\n" +
//                "QVd34pU/YyR0zPZ8iCADnL2EJM1JO1NuGXxZmr3jDktcWzAFEhQn+s8QBaCkUKc1\n" +
//                "0lR/mZOGUOQQKAUKm9zQtD7CECsyarBMHvriL+x1fIQBWH+yLXXCsQvcPJFVzc/L\n" +
//                "-----END CERTIFICATE-----\n";
        for (String filename : filenames) {
            InputStream caInput = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/" + filename + ".cer"));
            InputStream caInputSSL= new ByteArrayInputStream(ssl_key.getBytes());
            Certificate ca;
            try {
                ca = cf.generateCertificate(caInputSSL);
                System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
            } finally {
                caInput.close();
                caInputSSL.close();
            }

            keyStore.setCertificateEntry(filename, ca);
        }

        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        sslContext.init(null, tmf.getTrustManagers(), null);
    }

    public SSLContext getContext() {
        return sslContext;
    }
}
