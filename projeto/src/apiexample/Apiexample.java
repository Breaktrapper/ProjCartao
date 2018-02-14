/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package apiexample;

import pteidlib.*;
import java.io.*;

/**
 *
 * @author jonas
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

    public void PrintIDData(PTEID_ID idData) {
        System.out.println("Informações do cartão...\n");
        System.out.println("Número cartão: \n" + idData.cardNumber);
        System.out.println("PAN : \n" + idData.cardNumberPAN);
        
        System.out.println("\nInformações pessoais...\n");
        System.out.println("Nome:\n" + idData.name);
        System.out.println("Sexo:\n" + idData.sex);
        System.out.println("Altura:\n" + idData.height);
        System.out.println("Data de nascimento:\n" + idData.birthDate);
        System.out.println("País:\n" + idData.country);
        System.out.println("Nacionalidade:\n" + idData.nationality);
        System.out.println("Primeiro nome:\n" + idData.firstname);
        System.out.println("Primeiro nome do pai:\n" + idData.firstnameFather);
        System.out.println("Primeiro nome da mãe:\n" + idData.firstnameMother);
        System.out.println("Nome da mãe:\n" + idData.nameMother);
        System.out.println("Número BI:\n" + idData.numBI);
        System.out.println("NIF:\n" + idData.numNIF);
        System.out.println("Número SNS:\n" + idData.numSNS);
        System.out.println("Número SS:\n" + idData.numSS);
    }

    public void PrintCertData(PTEID_Certif certData) {
        System.out.println("Certificados...\n");
        System.out.println(""+certData.certifLabel);

        

    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        int ret = 0;
        Apiexample teste = new Apiexample();
        try {
            // test.TestCVC();

            pteid.Init("");

            //test.TestChangeAddress();
            // Don't check the integrity of the ID, address and photo (!)
            pteid.SetSODChecking(false);

            int cardtype = pteid.GetCardType();
            switch (cardtype) {
                case pteid.CARD_TYPE_IAS07:
                    System.out.println("IAS 0.7 card\n");
                    break;
                case pteid.CARD_TYPE_IAS101:
                    System.out.println("IAS 1.0.1 card\n");
                    break;
                case pteid.CARD_TYPE_ERR:
                    System.out.println("Unable to get the card type\n");
                    break;
                default:
                    System.out.println("Unknown card type\n");
            }

            System.out.println("//--- Informações pessoais e de cartão ---//\n");
            PTEID_ID idData = pteid.GetID();
            if (idData != null) {
                
                teste.PrintIDData(idData);

            }
            System.out.println("//--- Fotografia ---//\n");
            PTEID_PIC pic = pteid.GetPic();
            if(pic != null)
            {
                try
                {
                    String foto = "foto.jp2";
                    FileOutputStream outFile = new FileOutputStream(foto);
                    outFile.write(pic.picture);
                    outFile.close();
                    System.out.println("Foto criada com sucesso.");
                }
                catch(FileNotFoundException excep)
                {
                    System.out.println(excep.getMessage());
                }
            }
            System.out.println("//--- Certificados digitais ---//\n");
            PTEID_Certif[] certs = pteid.GetCertificates();
            for(int i = 0; i< certs.length;i++)
            {
                System.out.println("Certificado:"+certs[i].toString());
            }

//
//       // Write personal data
//       String data = "Hallo JNI";
//       pteid.WriteFile(filein, data.getBytes(), (byte)0x81);
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
