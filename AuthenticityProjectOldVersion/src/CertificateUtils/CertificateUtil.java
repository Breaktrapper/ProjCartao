/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CertificateUtils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
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
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

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

    //Get OCSP from the given X509Certificate
    //Usefull website: https://svn.cesecore.eu/svn/ejbca/tags/Rel_3_1_4/ejbca/doc/samples/ValidateCertUseOCSP.java <------------
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
