/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package AppPackage;

import java.io.ByteArrayInputStream;

/**
 *
 * @author João Saraiva
 */
public class ConverterFile {
    
    // Converts to java.security

    public static java.security.cert.X509Certificate convertToJava(javax.security.cert.X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
            java.security.cert.CertificateFactory cf
                    = java.security.cert.CertificateFactory.getInstance("X.509");
            return (java.security.cert.X509Certificate) cf.generateCertificate(bis);
        } catch (java.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateEncodingException e) {
        } catch (java.security.cert.CertificateException e) {
        }
        return null;
    }

// Converts to javax.security
    public static javax.security.cert.X509Certificate convertToJavax(java.security.cert.X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            return javax.security.cert.X509Certificate.getInstance(encoded);
        } catch (java.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateException e) {
        }
        return null;
    }

}
