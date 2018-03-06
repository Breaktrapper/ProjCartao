/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CertificateUtils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.Enumeration;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 *
 * @author João Saraiva
 */
public class CertificateUtil {

    public X509Certificate cert;

    public X509Certificate getCert() {
        return cert;
    }

    public CertificateUtil() {
    }

    //Get X509Certificate from file 
    public X509Certificate getCertificateFromFile(String path) throws CertificateException, FileNotFoundException {
        X509Certificate x509 = null;
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream(path);
            x509 = (X509Certificate) fact.generateCertificate(is);

        } catch (Exception e) {
            System.out.println("Can't construct X509 Certificate. "
                    + e.getMessage());
        }
        return x509;
    }

    public static CertificateDetails getCertificateDetails(String jksPath, String jksPassword) {

        CertificateDetails certDetails = null;

        try {

            boolean isAliasWithPrivateKey = false;
            KeyStore keyStore = KeyStore.getInstance("JKS");

            // Provide location of Java Keystore and password for access
            keyStore.load(new FileInputStream(jksPath), jksPassword.toCharArray());

            // iterate over all aliases
            Enumeration<String> es = keyStore.aliases();
            String alias = "";
            while (es.hasMoreElements()) {
                alias = (String) es.nextElement();
                // if alias refers to a private key break at that point
                // as we want to use that certificate
                if (isAliasWithPrivateKey = keyStore.isKeyEntry(alias)) {
                    break;
                }
            }

            if (isAliasWithPrivateKey) {

                KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
                        new KeyStore.PasswordProtection(jksPassword.toCharArray()));

                PrivateKey myPrivateKey = pkEntry.getPrivateKey();

                // Load certificate chain
                Certificate[] chain = keyStore.getCertificateChain(alias);

                certDetails = new CertificateDetails();
                certDetails.setPrivateKey(myPrivateKey);
                certDetails.setX509Certificate((X509Certificate) chain[0]);

            }

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        }

        return certDetails;
    }

    //Get the public key from a x509 certificate to a new file
    public void getKeyFromCert(String path) throws CertificateException, FileNotFoundException, IOException {
        X509Certificate x509 = getCertificateFromFile(path);
        PublicKey pk = x509.getPublicKey();
        FileOutputStream os = new FileOutputStream("key.key");
        os.write(pk.getEncoded());
        os.close();
    }

    //Prints the certification path from the certificates in a java keystore
    public void printCertPath(String keystore, String alias, String password) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        char[] storepass = password.toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystore), storepass);
        java.security.cert.Certificate[] cchain = ks.getCertificateChain(alias);
        List mylist = new ArrayList();
        for (int i = 0; i < cchain.length; i++) {
            mylist.add(cchain[i]);
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath cp = cf.generateCertPath(mylist);
        System.out.println(cp);

    }

    //Get OCSP from the given X509Certificate
    //Usefull websites: https://svn.cesecore.eu/svn/ejbca/tags/Rel_3_1_4/ejbca/doc/samples/ValidateCertUseOCSP.java <------------
    //https://www.digicert.com/util/utility-test-ocsp-and-crl-access-from-a-server.htm <------------------
    public void OCSP(String RootCACert, String OCSPServerCert, String cert) {
        try {
            CertPath cp = null;
            Vector certs = new Vector();
            URI ocspServer = null;

            // load the cert to be checked
            certs.add(getCertificateFromFile(cert));

            // handle location of OCSP server
            ocspServer = new URI(OCSPServerCert);
            System.out.println("Using the OCSP server at: " + OCSPServerCert);
            System.out.println("to check the revocation status of: "
                    + certs.elementAt(0));
            System.out.println();

            // init cert path
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            cp = (CertPath) cf.generateCertPath(certs);

            // load the root CA cert for the OCSP server cert
            X509Certificate rootCACert = getCertificateFromFile(RootCACert);

            // init trusted certs
            TrustAnchor ta = new TrustAnchor(rootCACert, null);
            Set trustedCertsSet = new HashSet();
            trustedCertsSet.add(ta);

            // init cert store
            Set certSet = new HashSet();
            X509Certificate ocspCert = getCertificateFromFile(OCSPServerCert);
            certSet.add(ocspCert);
            CertStoreParameters storeParams
                    = new CollectionCertStoreParameters(certSet);
            CertStore store = CertStore.getInstance("Collection", storeParams);

            // init PKIX parameters
            PKIXParameters params = null;
            params = new PKIXParameters(trustedCertsSet);
            params.addCertStore(store);

            // enable OCSP
            Security.setProperty("ocsp.enable", "true");
            if (ocspServer != null) {
                Security.setProperty("ocsp.responderURL", OCSPServerCert);
                Security.setProperty("ocsp.responderCertSubjectName",
                        ocspCert.getSubjectX500Principal().getName());
            }

            // perform validation
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            PKIXCertPathValidatorResult cpv_result
                    = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
            X509Certificate trustedCert = (X509Certificate) cpv_result.getTrustAnchor().getTrustedCert();

            if (trustedCert == null) {
                System.out.println("Trsuted Cert = NULL");
            } else {
                System.out.println("Trusted CA DN = "
                        + trustedCert.getSubjectDN());
            }

        } catch (CertPathValidatorException e) {
            e.printStackTrace();
            System.exit(1);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
        System.out.println("CERTIFICATE VALIDATION SUCCEEDED");
        System.exit(0);
    }
}
