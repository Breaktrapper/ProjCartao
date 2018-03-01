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
            System.out.println("//--- Leitura do ficheiro SOD ---//\n");
            byte[] sodFile = pteid.ReadSOD();
            helperFile.saveSOD(sodFile, "sodFile.der");
            
            System.out.println("//--- Certificados digitais ---//\n");

            PTEID_Certif[] certs = pteid.GetCertificates();
            System.out.println("Encontrados " + certs.length + " certificados!");
            X509Certificate x509 = X509Certificate.getInstance(certs[0].certif);
            System.out.println("\nCertificado " + 0 + ":" + "\nDN do Certificado: " + x509.getSubjectDN() + "\nDN do Emissor" + x509.getIssuerDN() + "\nValido até: " + x509.getNotAfter());
            helperFile.saveCerts(x509);
            
            for (int i = 0; i < certs.length; i++) {

                X509Certificate x509 = X509Certificate.getInstance(certs[i].certif);

                System.out.println("\nCertificado " + i + ":" + "\nDN do Certificado: " + x509.getSubjectDN() + "\nDN do Emissor" + x509.getIssuerDN() + "\nValido até: " + x509.getNotAfter());
                helperFile.saveCerts(x509);
            }
             

            //DIGESTS FROM CARD ID AND PUBLIK KEY
            byte[] keyDigest = null;

            PTEID_RSAPublicKey keyData = pteid.GetCardAuthenticationKey(); //Get PK
            PTEID_ID idData = pteid.GetID();
            if (idData != null) {
                Pteid_Person id = new Pteid_Person();
                id.parse_Person(idData);
                id.parse_Person_Key(keyData);
                keyDigest = id.getDigestPK_ICC_AUT();

                System.out.println("Key digest: " + ReleaseUtils.bytesToHex(keyDigest));

            }

            //DIGEST FROM CARD ADDRESS 
            //NOTE: Test card address pin ---> 3333
            PTEID_ADDR addressData = pteid.GetAddr();
            if (addressData != null) {
                Pteid_Address address = new Pteid_Address();
                address.parse_address(addressData);

            }
            
            //DIGEST FROM CARD PICTURE
            PTEID_PIC picData = pteid.GetPic();
            if (picData != null) {
                Pteid_Pic pic = new Pteid_Pic();
                pic.parse(picData);
            }
             */
            CertificateUtil certUtil = new CertificateUtil();
            String testCert = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\testFiles\\CartaoCidadao001.cer";
            String intermediateCert = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\testFiles\\ECRaizEstado.cer";
            String rootCert = "C:\\Users\\João Saraiva\\Documents\\GitHub\\ProjetoFinal\\AuthenticityProjectOldVersion\\testFiles\\MULTICERTRootCertificationAuthority01.cer";
            
            X509Certificate x509TestCert = certUtil.getCertificateFromFile(testCert);
            X509Certificate x509Intermediate = certUtil.getCertificateFromFile(intermediateCert);
            X509Certificate x509Root = certUtil.getCertificateFromFile(rootCert);
            
            
            Set <X509Certificate> CertificateSet = new HashSet <X509Certificate>(); 
            CertificateSet.add(x509Root);
            CertificateSet.add(x509Intermediate);
            
            List <String> CRLPoints = CRLVerifier.getCrlDistributionPoints(x509TestCert);
            //System.out.println(CRLPoints.toString());
            //CertificateVerifier.verifyCertificate(x509TestCert, CertificateSet);
            
            
            
            
            
            

        } catch (PteidException ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());
        } catch (Exception ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());

        }

    }
}
