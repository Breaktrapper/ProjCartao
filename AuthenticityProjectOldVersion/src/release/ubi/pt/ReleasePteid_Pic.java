/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package release.ubi.pt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Paul Crocker
 * 
#define PTEID_MAX_PICTURE_LEN			14128
#define PTEID_MAX_PICTURE_LEN_HEADER            111
#define PTEID_MAX_PICTUREH_LEN			(PTEID_MAX_PICTURE_LEN+PTEID_MAX_PICTURE_LEN_HEADER)
#define PTEID_MAX_CBEFF_LEN                     34
#define PTEID_MAX_FACRECH_LEN			14
#define PTEID_MAX_FACINFO_LEN			20
#define PTEID_MAX_IMAGEINFO_LEN			12
#define PTEID_MAX_IMAGEHEADER_LEN		(PTEID_MAX_CBEFF_LEN+PTEID_MAX_FACRECH_LEN+PTEID_MAX_FACINFO_LEN+PTEID_MAX_IMAGEINFO_LEN)

 * 
 */
public class ReleasePteid_Pic {

    //short version; //in looking at new middleware this value does not seem to be set anywhere ??
    //this is probable a bug in the new version or the old !!
    //the other version id for morada and id data are all set to zero statically
    
    public boolean cbeffValid = false;
    private byte[] digest=null;

    public byte[] getDigest() {
        return digest;
    }
    
    private byte[] cbeff=null;   
    private byte[] facialrechdr=null;
    private byte[] facialinfo=null;
    private byte[] imageinfo=null;
    private byte[] picture=null;
   
    public void setCbeffRest(byte []data)
    {
        if (data.length>=33)
        {
            System.arraycopy(data,0, this.cbeff, 0,33);
            cbeffValid = true;
        }
    }
    
    public void parse(byte[] data) 
    {
        parsePic(data, 0);
    }
    public void parsePic(byte[] data, int start) {
        
        //if we have read the previous block then start = 256
        //if we have started from the begining then start = 256*6
 
        //start=0;
        //start = 256
        //start = 256*6
        
        //check size of data !!!
                
        this.cbeff = new byte[34];
       
        if (start==0) //copy only the last byte
            System.arraycopy(data,0, this.cbeff, 33, 1);
        else {
            if (start == 256) {
                System.arraycopy(data, 223, this.cbeff, 0, 34);
            }
            if (start == 256 * 6) {
                System.arraycopy(data, 256 * 5 + 223, this.cbeff, 0, 34);
            }
            cbeffValid = true;
        }
      
        // System.out.println("cbeff:" + ReleaseUtils.bytesToHex(cbeff));
        
        this.facialrechdr = new byte[14];
        System.arraycopy(data, start+ 1, this.facialrechdr , 0, 14);
        //System.out.println("facialrechdr:" + ReleaseUtils.bytesToHex(facialrechdr));
        
        this.facialinfo = new byte[20];
        System.arraycopy(data, start + 1+14,  this.facialinfo, 0, 20);
         //System.out.println("facialinfo:" + ReleaseUtils.bytesToHex(facialinfo));
        
        this.imageinfo = new byte[12];
        System.arraycopy(data, start + 1+14+20,  this.imageinfo, 0, 12);
        // System.out.println("imageinfo:" + ReleaseUtils.bytesToHex(imageinfo));
        
        int lenOffset = 1583-1536;  //47              
       
        //search for the end of codestream "FF D9"
        boolean found=false;    
        int i = data.length -1;
        while (!found && i>0) {
            i--;
            if (((byte) (data[i] & 0xff) == (byte) 0xFF)) {
                if (((byte) (data[i + 1] & 0xff) == (byte) 0xD9)) 
                {
                    found = true;
                    i = i+2;
                } 
            }
            
        }
        
        this.picture = new byte[i-lenOffset-start];
        System.arraycopy(data, start + lenOffset, this.picture , 0, i - lenOffset-start);  
       // System.out.println("picture:" + ReleaseUtils.bytesToHex(picture));
        
        setDigest();
    }
    
    private void setDigest()
    {
          
            if (!cbeffValid) return;
            
            String hashAlgorithm = "SHA-256";
            MessageDigest sha1; // Compute digest
            try {
                sha1 = MessageDigest.getInstance(hashAlgorithm);
                sha1.update(cbeff);
                sha1.update(facialrechdr);
                sha1.update(facialinfo);
                sha1.update(imageinfo);
                sha1.update(picture);
                digest = sha1.digest();
                System.out.println("PIC (13997) length+"+"--"+"\nHash:" + ReleaseUtils.bytesToHex(digest));
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ReleasePteid_Pic.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        
    }

    public byte[] getCbeff() {
        return cbeff;
    }
     
    public byte[] getFacialinfo() {
        return facialinfo;
    }

    public byte[] getFacialrechdr() {
        return facialrechdr;
    }

    public byte[] getImageinfo() {
        return imageinfo;
    }

    public byte[] getPicture() {
        return picture;
    }
}
