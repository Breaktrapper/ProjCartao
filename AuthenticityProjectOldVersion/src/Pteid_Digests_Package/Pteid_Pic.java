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

    public byte[] cbeff = null;
    public byte[] facialrechdr = null;
    public byte[] facialinfo = null;
    private byte[] imageinfo = null;
    private byte[] picture = null;

    public byte[] getDigest() {
        return digest;
    }

    public Pteid_Pic() {
    }

    public void setDigest(byte[] digest) {
        this.digest = digest;
    }

}
