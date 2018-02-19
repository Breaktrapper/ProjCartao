/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package apiexample;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.security.cert.CertificateEncodingException;

import pt.gov.cartaodecidadao.PTEID_Certificate;
import pt.gov.cartaodecidadao.PTEID_Certificates;
import pt.gov.cartaodecidadao.PTEID_EIDCard;
import pt.gov.cartaodecidadao.PTEID_Exception;
import sun.misc.BASE64Encoder;

/**
 *
 * @author João Saraiva
 */
public class helperFile {

    private PTEID_EIDCard card;

    public static void saveSOD(byte[] bytes, String file) throws FileNotFoundException, IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(bytes);
        fos.close();
    }

    /*
    public X509Certificate[] getCardCertificates() throws PTEID_Exception, CertificateException {

        PTEID_Certificates certs = card.getCertificates();
        X509Certificate userCert = toJavaCertificate(certs.getCertFromCard(0));
        X509Certificate subCACert = toJavaCertificate(certs.getCertFromCard(3));
        return new X509Certificate[]{userCert, subCACert};
    }

    private X509Certificate toJavaCertificate(PTEID_Certificate certificate) throws CertificateException, PTEID_Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(certificate.getCertData().GetBytes());
        X509Certificate javaCert = (X509Certificate) cf.generateCertificate(is);

        return javaCert;
    }
     */
    /*
    public static void saveCerts(javax.security.cert.X509Certificate x509) throws FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {
        FileOutputStream os = new FileOutputStream("x509certs.cer");
        os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.write(Base64.encodeBase64(x509.getEncoded(), true));
        os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.close();

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null);

        InputStream bis = new FileInputStream("x509certs.cer");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while (bis.available() > 0) {
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
            trustStore.setCertificateEntry("fiddler" + bis.available(), cert);

        }
    }
    */

    public static boolean checkHashes(String file1, String file2) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        System.out.println("//---------- File 1 hash value: -------------//\n");
        byte[] buffer = new byte[8192];
        int count;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file1));
        while ((count = bis.read(buffer)) > 0) {
            digest.update(buffer, 0, count);
        }
        byte[] hash = digest.digest();
        //System.out.println("Valor de hash do ficheiro pic.jp2 " +new BASE64Encoder().encode(hash));

        System.out.println("//---------- File 2 hash value: -------------//\n");
        byte[] buffer2 = new byte[8192];
        int count2;
        MessageDigest digest2 = MessageDigest.getInstance("SHA-256");
        BufferedInputStream bis2 = new BufferedInputStream(new FileInputStream(file2));
        while ((count2 = bis2.read(buffer)) > 0) {
            digest2.update(buffer2, 0, count2);
        }
        byte[] hash2 = digest2.digest();
        
        if (hash.equals(hash2))
        {
            return true;
        }
        else
        {
            return false;
        }
            
        
        //System.out.println("Valor de hash do ficheiro pic.jp2 " +new BASE64Encoder().encode(hash));
    }
}

