/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Pteid_Digests_Package;

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

    private byte[] cbeff = null;
    private byte[] facialrechdr = null;
    private byte[] facialinfo = null;
    private byte[] imageinfo = null;
    private byte[] picture = null;

    public byte[] getDigest() {
        return digest;
    }

    public Pteid_Pic() {
    }

    public void parse(PTEID_PIC pic) {
        parsePic(pic, 0);
    }

    public void parsePic(PTEID_PIC pic, int start) {

        this.cbeff = new byte[34];

        if (start == 0) //copy only the last byte
        {
            System.arraycopy(pic.cbeff, 0, this.cbeff, 33, 1);
        } else {
            if (start == 256) {
                System.arraycopy(pic.cbeff, 223, this.cbeff, 0, 34);
            }
            if (start == 256 * 6) {
                System.arraycopy(pic.cbeff, 256 * 5 + 223, this.cbeff, 0, 34);
            }
            cbeffValid = true;
        }

        this.facialrechdr = new byte[14];
        System.arraycopy(pic.facialrechdr, start + 1, this.facialrechdr, 0, 14);

        this.facialinfo = new byte[20];
        System.arraycopy(pic.facialinfo, start + 1 + 14, this.facialinfo, 0, 20);

        this.imageinfo = new byte[12];
        System.arraycopy(pic.imageinfo, start + 1 + 14 + 20, this.imageinfo, 0, 12);

        int lenOffset = 1583 - 1536;  //47              

        //search for the end of codestream "FF D9"
        /*
        boolean found = false;
        int i = pic.picture.length - 1; //data = pic.picture?????
        while (!found && i > 0) {
            i--;
            if (((byte) (pic.picture[i] & 0xff) == (byte) 0xFF)) {
                if (((byte) (pic.picture[i + 1] & 0xff) == (byte) 0xD9)) {
                    found = true;
                    i = i + 2;
                }
            }

        }

        this.picture = new byte[i - lenOffset - start];
        System.arraycopy(pic.picture, start + lenOffset, this.picture, 0, i - lenOffset - start);
        // System.out.println("picture:" + ReleaseUtils.bytesToHex(picture));
        */
        setDigest();
    }

    private void setDigest() {

        if (!cbeffValid) {
            return;
        }

        String hashAlgorithm = "SHA-256";
        MessageDigest sha1; // Compute digest
        try {
            sha1 = MessageDigest.getInstance(hashAlgorithm);
            sha1.update(cbeff);
            sha1.update(facialrechdr);
            sha1.update(facialinfo);
            sha1.update(imageinfo);
            ///sha1.update(picture);
            digest = sha1.digest();
            System.out.println("PIC (13997) length+" + "--" + "\nHash: " + ReleaseUtils.bytesToHex(digest));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Pteid_Pic.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
