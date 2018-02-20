/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package apiexample;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.security.cert.X509Certificate;

import pt.gov.cartaodecidadao.PTEID_EIDCard;
import pteidlib.PTEID_Certif;
import pteidlib.PteidException;
import pteidlib.pteid;
import pteidlib.PTEID_PIC;

/**
 *
 * @author João Saraiva
 */
public class Apiexample {

    private PTEID_EIDCard card;
    public static X509Certificate teste = null;

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
            //test.TestChangeAddress();
            // Don't check the integrity of the ID, address and photo (!)

            pteid.Init("");
            pteid.SetSODChecking(false);

            System.out.println("//--- Leitura do ficheiro SOD ---//\n");

            byte[] ReadSOD = pteid.ReadSOD();
            helperFile.saveSOD(ReadSOD, "file.der");

            System.out.println("//--- Certificados digitais ---//\n");

            PTEID_Certif[] certs = pteid.GetCertificates();
            System.out.println("Encontrados " + certs.length + "certificados");
            for (int i = 0; i < certs.length; i++) {
                if (i == 0) {
                    teste = X509Certificate.getInstance(certs[i].certif);
                }
                X509Certificate x509 = X509Certificate.getInstance(certs[i].certif);
                System.out.println("\nCertificado " + i + ":" + "\nDN do Certificado: " + x509.getSubjectDN() + "\nDN do Emissor" + x509.getIssuerDN() + "\nValido até: " + x509.getNotAfter());
                helperFile.saveCerts(x509);
            }
            //Extrair OSCP para o certificado de teste
            //String oscp = helperFile.getOcspUrl(teste);

            PTEID_PIC picData = pteid.GetPic();
            if (null != picData) {
                try {
                    String photo = "pic.jp2";
                    FileOutputStream oFile = new FileOutputStream(photo);
                    oFile.write(picData.picture);
                    oFile.close();
                    System.out.println("Created " + photo);
                } catch (FileNotFoundException excep) {
                    System.out.println(excep.getMessage());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            boolean bool = helperFile.checkHashes("file.bin", "pic.jp2");
            if (bool == true) {
                System.out.println("Os ficheiros são iguais!\n");

            } else {
                System.out.println("Os ficheiros são diferentes!\n");
            }

//       pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD);
        } catch (PteidException ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());
        } catch (Exception ex) {
            ex.printStackTrace();
            //System.out.println(ex.getMessage());
        }
    }

    //TO DO LIST...
    //--------------- Parte 1 --------------------// 
    //gravar para o ficheiro binário
    //testar no online editor ans1 editor http://asn1-playground.oss.com/
    //- ver estrutura 
    //- java parsers https://www.openmuc.org/asn1/user-guide/
    //https://stackoverflow.com/questions/10190795/parsing-asn-1-binary-data-with-java
    //--------------- Parte 2 --------------------//
    //verificar os certificados1 (possivelmente cadeia, etc..)
    //extrair ocsp -- output    (
    //extrar crl -- output
    //gravar os certificados para o ficheiro
    //ver os formatos ..
    //ver a cadeia de certificados
    //ver se consegues inserir os certs num java keystore e verificar os certifcados e cadeia de certificação.
    //--------------- Parte 3 --------------------// DONE
    //obter hash do ID, pic, etc.. 
    //comparar com a hash do SOD
    //--------------- Duvidas...
    //1ª- O que significa CVC?
    //2ª- Qual a diferença entre PTEID_Certif[] GetCertificates() do pteid.java e PTEID_Certificate getCert do PTEID_Certificates.java??
    //3ª- Na função toJavaCertificate() e alterar o tipo do objeto para PTEID_Certif, não existe o metodo getCertData() logo não funciona..
}
