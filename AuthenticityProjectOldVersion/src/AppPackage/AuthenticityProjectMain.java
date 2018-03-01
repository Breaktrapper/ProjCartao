package AppPackage;

import Pteid_Digests_Package.Pteid_Address;
import java.io.IOException;
import javax.security.cert.X509Certificate;
import pt.gov.cartaodecidadao.PTEID_ByteArray;
import pteidlib.PTEID_ADDR;

import pteidlib.PTEID_Certif;
import pteidlib.PTEID_ID;
import pteidlib.PTEID_PIC;
import pteidlib.PteidException;
import pteidlib.pteid;

import Pteid_Digests_Package.Pteid_Person;
import Pteid_Digests_Package.Pteid_Pic;
import pteidlib.PTEID_RSAPublicKey;
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
             */

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
            /*
            //DIGEST FROM CARD PICTURE
            PTEID_PIC picData = pteid.GetPic();
            if (picData != null) {
                Pteid_Pic pic = new Pteid_Pic();
                pic.parse(picData);
            }
             */

        } catch (PteidException ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());
        } catch (Exception ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());

        }

    }
}
