package AppPackage;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.PKIXCertPathBuilderResult;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;


import CertificateUtils.CRLVerifier;
import CertificateUtils.CertificateUtil;
import CertificateUtils.CertificateVerifier;


import pteidlib.PTEID_ADDR;
import pteidlib.PTEID_Certif;
import pteidlib.PTEID_ID;
import pteidlib.PTEID_PIC;
import pteidlib.PteidException;
import pteidlib.pteid;

import Pteid_Digests_Package.Pteid_Person;
import Pteid_Digests_Package.Pteid_Pic;
import Pteid_Digests_Package.Pteid_Address;


import pteidlib.PTEID_RSAPublicKey;
import release.ubi.pt.ReleasePteid_Validate;
import release.ubi.pt.ReleaseUtils;

import sun.security.provider.certpath.OCSP;

/**
 * @author João Saraiva - FEITO COM A VERSÃO ANTIGA DO MIDDLEWARE DO GOVERNO
 */
public class AuthenticityProjectMain {


    public static byte[] testSignature = null;

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
            
            //------------------------------------------------ SOD File and Digital Certificates from CITIZEN CARD --------------------------------------------------------- //
            /*
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

                X509Certificate x509_2 = X509Certificate.getInstance(certs[i].certif);
                System.out.println("\nCertificado " + i + ":" + "\nDN do Certificado: " + x509_2.getSubjectDN() + "\nDN do Emissor" + x509_2.getIssuerDN() + "\nValido até: " + x509_2.getNotAfter());
                helperFile.saveCerts(x509);
            }
            
            
            //------------------------------------------------ Hashes from citizen card informations and validations --------------------------------------------------------- //

            //------------------------------------------------------------------- RELEASE PTEID VALIDATE -----------------------------------------------
            //DIGESTS FROM CARD ID AND PUBLIC KEY
            byte[] personDigest = null;
            byte[] keyDigest = null;
            byte[] picDigest = null;
            byte[] addressDigest = null;

            //Get key
            PTEID_RSAPublicKey keyData = pteid.GetCardAuthenticationKey();

            //Get ID object from card
            PTEID_ID idData = pteid.GetID();
            Pteid_Person person = new Pteid_Person(); //New Pteid_Person constructor

            //Calculate the digests for the personal information and the public key
            person.parse_Person(idData);
            person.parse_Person_Key(keyData);

            //Get the person and PK digests
            personDigest = person.getDigest();
            keyDigest = person.getDigestPK_ICC_AUT();

            //Print the key digest
            System.out.println("KEY Hash: " + ReleaseUtils.bytesToHex(keyDigest));

            //DIGEST FROM CARD ADDRESS 
            //------------------------------------------------------------------- NOTE: Test card address pin ---> 3333 ------------------------------- //
            //Get ADDR object from card
            PTEID_ADDR addressData = pteid.GetAddr();
            Pteid_Address address = new Pteid_Address(); //New Pteid_Address constructor

            //Calculate the hash for the address information
            address.parse_address(addressData);

            //Get the address digest
            addressDigest = address.getDigest();

            //DIGEST FROM CARD PICTURE
            //Get PIC object from card
            PTEID_PIC picData = pteid.GetPic();
            Pteid_Pic pic = new Pteid_Pic();
            pic.parse_Pic(picData);
            picDigest = pic.getDigest();

            System.out.println("//---------------------------------------------------------------------------------------------------------------//\n");

            byte[] personArray = person.getDataArray();
            byte[] addressArray = address.getDataArray();
            byte[] picArray = pic.getDataArray();
            byte[] keyArray = person.getPK_ICC_AUT();

            //Create new ReleasePteid_Validate construtor in debug mode -> true
            ReleasePteid_Validate releaseValidate = new ReleasePteid_Validate(true);

            //ReleasePteid_Validate method: refresh()
            //-> Get SOD file from citizen card (as a PKCS7 object)
            //-> Get digital certificate/s from card
            //-> Get the 4 hashes from the ID, Address, Pic and Key
            //-> Create the hash of the four hash block ---> (byte[] fourHashDataDigest = sha256Instance.digest(dataBytes);)
            //-> Create the hash of the four hashes in the authenticated block -> (PKCS9Attribute[] attributes = authenticatedAttributes.getAttributes();)
            //-> Get the signature and decrypt it
            //-> Create the hash of the signed data block to validate the decrypted signature
            releaseValidate.refresh();

            //TESTING HASHES STUFF....
            
            //-------------------------------------------------------------------->   Byte [] with the 4 Pteid Information arrays concatenated
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(personArray);
            outputStream.write(addressArray);
            outputStream.write(picArray);
            outputStream.write(keyArray);
            byte[] array1 = outputStream.toByteArray();

            byte[] fourHashDataBlock = null;
            String hashAlgorithm = "SHA-256";
            MessageDigest sha1; // Compute digest
            try {
                sha1 = MessageDigest.getInstance(hashAlgorithm);
                fourHashDataBlock = sha1.digest(array1);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(AuthenticityProjectMain.class.getName()).log(Level.SEVERE, null, ex);
            }
            //--------------------------------------------------------------------> Byte [] with the 4 digests of PTEID info concatenated
            ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
            outputStream2.write(personDigest);
            outputStream2.write(addressDigest);
            outputStream2.write(picDigest);
            outputStream2.write(keyDigest);
            byte[] array2 = outputStream2.toByteArray();
            
            byte[] fourHashDataBlock2 = null;
            String hashAlgorithm2 = "SHA-256";
            MessageDigest sha2; // Compute digest
            try {
                sha2 = MessageDigest.getInstance(hashAlgorithm2);
                fourHashDataBlock2 = sha2.digest(array2);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(AuthenticityProjectMain.class.getName()).log(Level.SEVERE, null, ex);
            }

            

            //Four hash block from SOD
            byte[] sodHashArray = releaseValidate.getFourHashDataDigestSOD();
            if (Arrays.equals(fourHashDataBlock2, sodHashArray)) {
                System.out.println("ARE EQUAL.");
            } 
            //Get signature from SOD PKCS7 object
            testSignature = releaseValidate.getSignature();
            System.out.println("Signature: " + ReleaseUtils.bytesToHex(testSignature));

            X509Certificate publicCertificate = releaseValidate.getDocumentCertificate();

            byte[] certificateSignature = null;
            certificateSignature = publicCertificate.getSignature();
            if (Arrays.equals(certificateSignature, testSignature)) {
                System.out.println("Signatures validated");
            } else {
                System.out.println("Signatures not validated"); //??????????????????
            }

            boolean validCert = releaseValidate.getDocumentCertificateValidty();  //It is if the current date and time are within the validity period given in the certificate.
            if (validCert == true) {
                System.out.println("Certificate is valid.");
                certificateSignature = publicCertificate.getSignature();
                if (Arrays.equals(certificateSignature, testSignature)) {
                    System.out.println("Signatures validated");
                } else {
                    System.out.println("Signatures not validated");
                }

            } else {
                System.out.println("Certificate is not valid.");
            }
            */
            
            //-------------------------------------- CRL and certification chain
            //
            //-------------------------------------- Certification Chain ------------------------------------------------------------ //
            //Usefull website: http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
            //
            //New CertificateUtil constructor
            CertificateUtil certUtil = new CertificateUtil();

            //Get test, root and intermediate certificate paths
            String testCert = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\Certificates\\TestCertificate\\TestCert.cer";
            String rootCert = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\Certificates\\RootCertificates\\RootCert.cer";

            String testCert_CC = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\Certificates\\TestCertificate\\TestCertCC.cer";
            
            //Get the certificates from the files
            X509Certificate x509TestCert = certUtil.getCertificateFromFile(testCert);
            X509Certificate x509Root = certUtil.getCertificateFromFile(rootCert);
            X509Certificate x509TestCert_CC = certUtil.getCertificateFromFile(testCert_CC);
            

            //Create a new set of X509Certificate objects
            Set<X509Certificate> CertificateSet = new HashSet<X509Certificate>();

            //Add the above certificates to the Set
            CertificateSet.add(x509TestCert);
            CertificateSet.add(x509Root);

            //Build the certification chain for the given test certificate and the trusted root CA certificates and also the intermediate certificates
            //Verify the chain
            //PKIXCertPathBuilderResult chain = CertificateVerifier.verifyCertificate(x509TestCert, CertificateSet);
            //CertPath certPath = chain.getCertPath();
            //System.out.println("Certificate path: " + certPath); //PROBLEM: Can't verify the test certificate using the trusted root CA certificates and intermediate certificates

            //----------------------------------- CRL Distribution Point URL's -------------------------------------------------//
            //Extracts all CRL distribution point URLs from the certificate
            //List<String> CRLPoints = CRLVerifier.getCrlDistributionPoints(x509TestCert);
            //System.out.println(CRLPoints.toString());
            
            //----------------------------------- OCSP testing -------------------------------------------------------------------------//
            OCSP.RevocationStatus check = OCSP.check(x509TestCert, x509Root);
            OCSP.RevocationStatus.CertStatus certStatus = check.getCertStatus();
            certStatus.toString();
            
            

        } catch (PteidException ex) {
            ex.printStackTrace();
            System.out.println(ex.getMessage());
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println(ex.getMessage());

        }

    }
}
