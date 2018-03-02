package AppPackage;

import CertificateUtils.CRLVerifier;
import CertificateUtils.CertificateUtil;
import CertificateUtils.CertificateVerifier;
import java.io.IOException;
import java.security.cert.X509Certificate;

import pteidlib.PTEID_ADDR;
import pteidlib.PTEID_Certif;
import pteidlib.PTEID_ID;
import pteidlib.PTEID_PIC;
import pteidlib.PteidException;
import pteidlib.pteid;

import Pteid_Digests_Package.Pteid_Person;
import Pteid_Digests_Package.Pteid_Pic;
import Pteid_Digests_Package.Pteid_Address;
import java.security.cert.CertPath;
import java.security.cert.PKIXCertPathBuilderResult;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import release.ubi.pt.ReleaseUtils;

/**
 * @author João Saraiva - FEITO COM A VERSÃO ANTIGA DO MIDDLEWARE DO GOVERNO
 */
public class AuthenticityProjectMain {

    //Load system library..
    static {
        try {
            System.loadLibrary("pteidlibj");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }
    }

    public static void main(String[] args) throws IOException {

        try {
            //Inicilize card
            pteid.Init("");
            pteid.SetSODChecking(false);
            /*
            //------------------------------------------------ SOD File and Digital Certificates from CITIZEN CARD --------------------------------------------------------- //
            
            //Get bytes from card for the SOD File
            byte[] sodFile = pteid.ReadSOD();
            
            //Save into a new .der encoded file
            helperFile.saveSOD(sodFile, "sodFile.der");
            
            //Get all the digital certificates from the citizen card
            PTEID_Certif[] certs = pteid.GetCertificates();
            System.out.println("Encontrados " + certs.length + " certificados!");
            X509Certificate x509 = X509Certificate.getInstance(certs[0].certif);
            System.out.println("\nCertificado " + 0 + ":" + "\nDN do Certificado: " + x509.getSubjectDN() + "\nDN do Emissor" + x509.getIssuerDN() + "\nValido até: " + x509.getNotAfter());
            
            //Save each one of them in a new file
            helperFile.saveCerts(x509);
            
            //List them, for testing....
            for (int i = 0; i < certs.length; i++) {

                X509Certificate x509 = X509Certificate.getInstance(certs[i].certif);
                System.out.println("\nCertificado " + i + ":" + "\nDN do Certificado: " + x509.getSubjectDN() + "\nDN do Emissor" + x509.getIssuerDN() + "\nValido até: " + x509.getNotAfter());
                helperFile.saveCerts(x509);
            }
            //--------------------------------------------------------------------------------------------------------------------------------------------------------------- //
            //------------------------------------------------ Hashes from citizen card informations  --------------------------------------------------------- //

            //DIGESTS FROM CARD ID AND PUBLIC KEY
            byte[] keyDigest = null;

            //Get key
            PTEID_RSAPublicKey keyData = pteid.GetCardAuthenticationKey(); 
            
            //Get ID object from card
            PTEID_ID idData = pteid.GetID();
            if (idData != null) 
            {
                //New Pteid_Person constructor
                Pteid_Person id = new Pteid_Person();
                
                //Calculate the digests for the personal information and the public key
                id.parse_Person(idData);
                id.parse_Person_Key(keyData);
            
                //Calculate the digest byte array
                keyDigest = id.getDigestPK_ICC_AUT();
            
                //Print the key digest
                System.out.println("Key digest: " + ReleaseUtils.bytesToHex(keyDigest)); 
            }

            //DIGEST FROM CARD ADDRESS 
            //------------------------------------------------------------------- NOTE: Test card address pin ---> 3333 ------------------------------- //
            //Get ADDR object from card
            PTEID_ADDR addressData = pteid.GetAddr();
            if (addressData != null) 
            {
                Pteid_Address address = new Pteid_Address();
            
                //Calculate the hash for the address information
                address.parse_address(addressData);

            }
            
            //DIGEST FROM CARD PICTURE
            
            //Get PIC object from card
            PTEID_PIC picData = pteid.GetPic();
            if (picData != null) 
            {
                Pteid_Pic pic = new Pteid_Pic();
                //Calculate the hash for the picture -------------->> NOT WORKING 100%
                pic.parse(picData);
            }
            

            //-------------------------------------- CRL and certification chain
            //
            //-------------------------------------- Certification Chain ------------------------------------------------------------ //
            //Usefull website: http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
            //
            */
            //New CertificateUtil constructor
            CertificateUtil certUtil = new CertificateUtil();
            
            //Get test, root and intermediate certificate paths
            String testCert = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\Certificates\\TestCertificate\\ECAutenticacaoCCIntermediateCert.cer";
            String intermediateCert = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\Certificates\\IntermediateCertificates\\CC003.cer";
            String intermediateCert2 = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\Certificates\\IntermediateCertificates\\IntermediateCert.cer";
            String rootCert = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\Certificates\\RootCertificates\\RootCert.cer";
            
            //Get tbhe certificates from the files
            X509Certificate x509TestCert = certUtil.getCertificateFromFile(testCert);
            X509Certificate x509Intermediate = certUtil.getCertificateFromFile(intermediateCert);
            X509Certificate x509Intermediate2 = certUtil.getCertificateFromFile(intermediateCert2);
            X509Certificate x509Root = certUtil.getCertificateFromFile(rootCert);

            //Create a new set of X509Certificate objects
            Set<X509Certificate> CertificateSet = new HashSet<X509Certificate>();

            //Add the above certificates to the Set
            CertificateSet.add(x509Root);
            CertificateSet.add(x509Intermediate);
            CertificateSet.add(x509Intermediate2);

            //Build the certification chain for the given test certificate and the trusted root CA certificates and also the intermediate certificates
            //Verify the chain
            PKIXCertPathBuilderResult chain = CertificateVerifier.verifyCertificate(x509TestCert, CertificateSet);
            CertPath certPath = chain.getCertPath(); 
            System.out.println("Certificate path: " + certPath); //PROBLEM: Can't verify the test certificate using the trusted root CA certificates and intermediate certificates

            //----------------------------------- CRL Distribution Point URL's -------------------------------------------------//
            //Extracts all CRL distribution point URLs from the certificate
            /*
            List<String> CRLPoints = CRLVerifier.getCrlDistributionPoints(x509TestCert);
            System.out.println(CRLPoints.toString());
            
            //----------------------------------- OCSP -------------------------------------------------------------------------//
            certUtil.OCSP(rootCert, "http://ocsp.root.cartaodecidadao.pt/publico/ocsp", testCert);
            */
//WHERE TO USE THIS "http://ocsp.root.cartaodecidadao.pt/publico/ocsp"?
        } catch (PteidException ex) {
            ex.printStackTrace();
            System.out.println(ex.getMessage());
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println(ex.getMessage());

        }

    }
}
