/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Pteid_Digests_Package;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import pteidlib.PTEID_PIC;
import release.ubi.pt.ReleaseUtils;

/**
 *
 * @author jonas
 */
public class Pteid_Pic {

    public boolean cbeffValid = false;
    private byte[] digest = null;

    public byte[] cbeff = null;
    public byte[] facialrechdr = null;
    public byte[] facialinfo = null;
    private byte[] imageinfo = null;
    private byte[] picture = null;

    public byte[] getDigest() {
        return digest;
    }

    public byte[] dataArray;

    public byte[] getDataArray() {
        return dataArray;
    }

    public Pteid_Pic() {
    }

    public void parse_Pic(PTEID_PIC pic) throws IOException {

        if (pic == null) {
            System.out.println("Objeto vazio..");
            return;
        }
        this.cbeff = pic.cbeff;
        this.facialinfo = pic.facialinfo;
        this.facialrechdr = pic.facialrechdr;
        this.imageinfo = pic.imageinfo;
        this.picture = pic.picture;

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        byteOut.write(this.cbeff);
        byteOut.write(this.facialinfo);
        byteOut.write(this.facialrechdr);
        byteOut.write(this.imageinfo);
        byteOut.write(this.picture);

        this.dataArray = byteOut.toByteArray();
        setDigest(byteOut.toByteArray());
    }

    public void setDigest(byte dataSodCheck[]) {//Calculate the hash for the picture 
        String hashAlgorithm = "SHA-256";
        MessageDigest sha1; // Compute digest
        try {
            sha1 = MessageDigest.getInstance(hashAlgorithm);
            digest = sha1.digest(dataSodCheck);
            System.out.println("PIC Hash: " + ReleaseUtils.bytesToHex(digest));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Pteid_Address.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
