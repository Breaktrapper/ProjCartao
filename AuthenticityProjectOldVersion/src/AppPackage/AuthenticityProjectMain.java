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
import pteidlib.PTEID_RSAPublicKey;
import release.ubi.pt.ReleasePteid_Validate;

import release.ubi.pt.ReleaseUtils;

/**
 * @author João Saraiva - FEITO COM A VERSÃO ANTIGA DO MIDDLEWARE DO GOVERNO
 */
public class AuthenticityProjectMain {

    public static byte[][] SODHashes = null;
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
            if (picData != null) {
                //Calculate the hash for the picture 
                String hashAlgorithm = "SHA-256";
                MessageDigest sha1; // Compute digest
                try {
                    sha1 = MessageDigest.getInstance(hashAlgorithm);
                    sha1.update(picData.cbeff);
                    sha1.update(picData.facialrechdr);
                    sha1.update(picData.facialinfo);
                    sha1.update(picData.imageinfo);
                    sha1.update(picData.picture);
                    picDigest = sha1.digest();
                    System.out.println("PIC hash: " + ReleaseUtils.bytesToHex(picDigest));
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Pteid_Pic.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            System.out.println("//---------------------------------------------------------------------------------------------------------------//\n");

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

            SODHashes = releaseValidate.getSodHashes();
            //System.out.println("SOD HASHES: "+ReleaseUtils.bytesToHex(SODHashes[0]));
            boolean test = releaseValidate.checkPerson(SODHashes, personDigest); //Compare (SODHashes[0] -> person digest from the SOD file) and the person digest from the card
            if (test == true) {
                System.out.println("hashes validated.");
            } else {
                System.out.println("not validated");
            }
            //Byte [] with the 4 digests from PTEID infomation in the card
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(personDigest);
            outputStream.write(addressDigest);
            outputStream.write(picDigest);
            outputStream.write(keyDigest);    //Talvez seja melhor primeiro meter num byte array antes de calcular o digest e usar esses arrays para formar um novo e comparar o digest desse array com o outro

            byte[] fourPteidHashBlock = outputStream.toByteArray();

            //Four hash block from SOD
            byte[] sodHashArray = releaseValidate.getFourHashDataDigest();
            if (Arrays.equals(fourPteidHashBlock, sodHashArray)) {
                System.out.println("hashes validated.");
            } else {
                System.out.println("not validated");
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
            /*
            boolean validCert = releaseValidate.getDocumentCertificateValidty();  //It is if the current date and time are within the validity period given in the certificate.
            if (validCert == true) {
                System.out.println("Certificate is valid.");
                certificateSignature = certificate.getSignature();
                if (Arrays.equals(certificateSignature, testSignature)) {
                    System.out.println("Signatures validated");
                }
                else
                {
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

            //Get the certificates from the files
            X509Certificate x509TestCert = certUtil.getCertificateFromFile(testCert);
            X509Certificate x509Root = certUtil.getCertificateFromFile(rootCert);

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
            List<String> CRLPoints = CRLVerifier.getCrlDistributionPoints(x509TestCert);
            System.out.println(CRLPoints.toString());

            //----------------------------------- OCSP -------------------------------------------------------------------------//
            certUtil.OCSP(rootCert, "http://ocsp.root.cartaodecidadao.pt/publico/ocsp", testCert);

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
