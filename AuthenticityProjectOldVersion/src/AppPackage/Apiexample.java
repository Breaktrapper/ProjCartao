package AppPackage;

import java.io.IOException;
import javax.security.cert.X509Certificate;

import pteidlib.PTEID_Certif;
import pteidlib.PteidException;
import pteidlib.pteid;

/**
 * @author João Saraiva - FEITO COM A VERSÃO ANTIGA DO MIDDLEWARE DO GOVERNO
 */
public class Apiexample {

    //Variables
    private byte[][] sodHashes = null;
    private X509Certificate documentCertificate = null;

    //Getters
    public X509Certificate getDocumentCertificate() {
        return documentCertificate;
    }

    public byte[][] getSodHashes() {
        return sodHashes;
    }

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

            System.out.println("//--- Leitura do ficheiro SOD ---//\n");

            byte[] sodFile = pteid.ReadSOD();
            helperFile.saveSOD(sodFile, "sodFile.der");

            System.out.println("//--- Certificados digitais ---//\n");

            PTEID_Certif[] certs = pteid.GetCertificates();
            System.out.println("Encontrados " + certs.length + " certificados!");
            for (int i = 0; i < certs.length; i++) {

                X509Certificate x509 = X509Certificate.getInstance(certs[i].certif);

                //X509Certificate x509 = X509Certificate.getInstance(certs[i].certif); ----> biblioteca javax
                System.out.println("\nCertificado " + i + ":" + "\nDN do Certificado: " + x509.getSubjectDN() + "\nDN do Emissor" + x509.getIssuerDN() + "\nValido até: " + x509.getNotAfter());
                helperFile.saveCerts(x509);
            }

        } catch (PteidException ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());
        } catch (Exception ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());

        }

    }

}
//Notas: É impossivel usar a biblioteca java.security.cert.X509Certificate, pelo menos para gravar os certificados pois não existe método como o getInstance(byte []...)
