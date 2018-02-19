/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package apiexample;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import pteidlib.PTEID_Certif;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 *
 * @author João Saraiva
 */
public class saveInfo {

    public static void saveSOD(byte[] bytes, String file) throws FileNotFoundException, IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(bytes);
        fos.close();
    }

    public static void saveCerts(PTEID_Certif[] certs, String file) throws FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        FileOutputStream fos = new FileOutputStream(file);
        for (int i = 0; i < certs.length; i++) {
            fos.write(certs[i].certif);
        }
        /*
        FileInputStream fis = null;
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fis, "my-keystore-password".toCharArray());

        String alias = "myalias";
        char[] password = "password".toCharArray();
        for (int j = 0; j < certs.length; j++) {

            keyStore.setCertificateEntry(alias, certs[j].certif); //CONVERTER PTEID_Cert[j] para Certificate para se poder guardar na keystore
        }
        FileOutputStream out = new FileOutputStream("my.keystore");
        keyStore.store(out, password);
        out.close();
        */
    }
}
