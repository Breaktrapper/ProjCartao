/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package AppPackage;

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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateParsingException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import sun.security.pkcs.*;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
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

    public static void saveSOD(byte[] bytes, String file) throws FileNotFoundException, IOException {
        FileOutputStream fos = new FileOutputStream(file);

        int k = 4;

        byte[] newSod = new byte[bytes.length - k];
        System.arraycopy(bytes, k, newSod, 0, bytes.length - k);

        fos.write(newSod);
        fos.close();

        PKCS7 p7 = new PKCS7(newSod);

        X509Certificate[] certificates = p7.getCertificates(); //Certificados do ficheiro SOD

        AlgorithmId[] digestAlgorithmIds = p7.getDigestAlgorithmIds();

        //System.out.println("P7 get Version: " + p7.getVersion().toString());
        System.out.println("Dump Object\n" + p7.toString());
        //using bouncycastle to dump the object
        ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(newSod));
        ASN1Object obj2 = (ASN1Object) bIn.readObject();
        System.out.println(ASN1Dump.dumpAsString(obj2, true));
        System.out.println("certificates (devia ser 1)" + certificates.length);
        System.out.println("certificates[0] subject DN " + certificates[0].getSubjectDN());

        int certLength;
        try {
            certLength = certificates[0].getEncoded().length;
            System.out.println("certificates[0] len " + certLength);

            for (int i = 0; i < digestAlgorithmIds.length; i++) {
                System.out.println("Digest Algorithms ids: " + digestAlgorithmIds[i].getName());
            }
        } catch (java.security.cert.CertificateEncodingException ex) {
            Logger.getLogger(helperFile.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static void saveCerts(javax.security.cert.X509Certificate x509) throws FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {
        FileOutputStream os = new FileOutputStream("testCert.cer");
        os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
        java.security.cert.X509Certificate x509toJava = ConverterFile.convertToJava(x509); //Converter de javax para java x509Certificate
        os.write(org.bouncycastle.util.encoders.Base64.encode(x509.getEncoded()));
        //os.write(Base64.encodeBase64(x509.getEncoded(), true));
        os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.close();

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "123456".toCharArray();

        FileInputStream store = new FileInputStream("keystore.jks");
        trustStore.load(store, password);
        FileInputStream bis = new FileInputStream("testCert.cer");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while (bis.available() > 0) {
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
            trustStore.setCertificateEntry("fiddler" + bis.available(), cert);

        }

        //trustStore.load(null);
    }

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

        if (hash.equals(hash2)) {
            return true;
        } else {
            return false;
        }
        //System.out.println("Valor de hash do ficheiro pic.jp2 " +new BASE64Encoder().encode(hash));
    }

    //CRL
    public static List<String> getCrlDistributionPoints(X509Certificate cert) throws CertificateParsingException, IOException {
        byte[] crldpExt = cert
                .getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        if (crldpExt == null) {
            return new ArrayList<String>();
        }
        ASN1InputStream oAsnInStream = new ASN1InputStream(
                new ByteArrayInputStream(crldpExt));
        ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
        DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
        byte[] crldpExtOctets = dosCrlDP.getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(
                new ByteArrayInputStream(crldpExtOctets));
        ASN1Primitive derObj2 = oAsnInStream2.readObject();
        CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
        List<String> crlUrls = new ArrayList<String>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] genNames = GeneralNames.getInstance(
                        dpn.getName()).getNames();
                // Look for an URI
                for (int j = 0; j < genNames.length; j++) {
                    if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(
                                genNames[j].getName()).getString();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }

    public static String getOcspUrl(X509Certificate certificate) throws Exception {
        byte[] octetBytes = certificate
                .getExtensionValue(X509Extension.authorityInfoAccess.getId());

        DLSequence dlSequence = null;
        ASN1Encodable asn1Encodable = null;

        try {
            ASN1Primitive fromExtensionValue = X509ExtensionUtil
                    .fromExtensionValue(octetBytes);
            if (!(fromExtensionValue instanceof DLSequence)) {
                return null;
            }
            dlSequence = (DLSequence) fromExtensionValue;
            for (int i = 0; i < dlSequence.size(); i++) {
                asn1Encodable = dlSequence.getObjectAt(i);
                if (asn1Encodable instanceof DLSequence) {
                    break;
                }
            }
            if (!(asn1Encodable instanceof DLSequence)) {
                return null;
            }
            dlSequence = (DLSequence) asn1Encodable;
            for (int i = 0; i < dlSequence.size(); i++) {
                asn1Encodable = dlSequence.getObjectAt(i);
                if (asn1Encodable instanceof DERTaggedObject) {
                    break;
                }
            }
            if (!(asn1Encodable instanceof DERTaggedObject)) {
                return null;
            }
            DERTaggedObject derTaggedObject = (DERTaggedObject) asn1Encodable;
            byte[] encoded = derTaggedObject.getEncoded();
            if (derTaggedObject.getTagNo() == 6) {
                int len = encoded[1];
                return new String(encoded, 2, len);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}
