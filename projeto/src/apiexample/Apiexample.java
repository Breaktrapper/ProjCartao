/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package apiexample;

import pteidlib.PTEID_Certif;
import java.io.*;
import pt.gov.cartaodecidadao.*;
import pteidlib.PteidException;
import pteidlib.pteid;

/**
 *
 * @author João Saraiva
 */
public class Apiexample {

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
            // test.TestCVC();

            pteid.Init("");

            //test.TestChangeAddress();
            // Don't check the integrity of the ID, address and photo (!)
            pteid.SetSODChecking(false);

            System.out.println("//--- Leitura do ficheiro SOD ---//\n");
            byte[] ReadSOD = pteid.ReadSOD();
            
            saveInfo.saveSOD(ReadSOD, "file.bin"); //gravar para o ficheiro binário
            //saveInfo.saveSOD(ReadSOD, "file.ber"); //Para testar no online editor -> online ans1 editor http://asn1-playground.oss.com/
            //ver estrutura 
            //java parsers https://www.openmuc.org/asn1/user-guide/
            //https://stackoverflow.com/questions/10190795/parsing-asn-1-binary-data-with-java

            System.out.println("//--- Certificados digitais ---//\n");
            PTEID_Certif[] certs = pteid.GetCertificates();
            saveInfo.saveCerts(certs, "certs.pem");

            //verificar os certifcado ?? (possivelmente cadeia, etc..)
            //extrair ocsp -- output
            //extrar crl -- output
            //gravar os certifcados para o ficheiro
            //ver os formatos ..
            //ver a cadeia de certificados
            //ver se consegues inserir os certs num java keystore e verificar os certifcados e cadeia de certificação.
            
            //MAIS TARDE..
            //obter hash do ID, pic, etc.. 
            //comparar com a hash do SOD
            /*
            for (int i = 0; i < certs.length; i++) {
                System.out.println(certs[i].certifLabel); //cadeia??
            }
            PTEID_Certificates certs2 = pt.gov.cartaodecidadao.PTEID_Certificates;
            PTEID_Certificate root = certs2.getRoot(); //obtem raiz
            PTEID_Certificate ca = certs2.getCA(); //obtem CA

            System.out.println("Root: " + root.toString());
            System.out.println("Ca:" + root.toString());
            */
            PTEID_Certificate certs4 = pt.gov.cartaodecidadao.PTEID_Certificate;
            String chain = certs4.getOwnerName();
            PTEID_CertifStatus status = certs4.getStatus();
            System.out.println("Status: "+status.toString());
//
//       pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD);
        } catch (PteidException ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());
        } catch (Exception ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());
        }
    }

}
