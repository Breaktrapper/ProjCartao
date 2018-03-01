/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package release.ubi.pt;

import Pteid_Digests_Package.Pteid_Address;
import Pteid_Digests_Package.Pteid_Person;
import Pteid_Digests_Package.Pteid_Pic;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.smartcardio.CardException;
import pteidlib.PteidException;
import sun.security.pkcs.*;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
//import org.bouncycastle.asn1.ASN1InputStream;
//import org.bouncycastle.asn1.ASN1Object;
//import org.bouncycastle.asn1.util.ASN1Dump;

import pteidlib.pteid;

/**
 *
 * @author Paul Crocker
 */
public  class ReleasePteid_Validate {

    private byte[][] sodHashes = null;
    private X509Certificate documentCertificate = null;

    public ReleasePteid_Validate() {
    }

    public X509Certificate getDocumentCertificate() {
        return documentCertificate;
    }
    public boolean getDocumentCertificateValidty() {
       //This checks that the certificate is currently valid. 
       //It is if the current date and time are within the validity period given in the certificate.
        try {
            documentCertificate.checkValidity();
            return true;
        } catch (CertificateExpiredException ex) {
            Logger.getLogger(ReleasePteid_Validate.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateNotYetValidException ex) {
            Logger.getLogger(ReleasePteid_Validate.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        /*
         * Tto validate an X.509 certificate.

            A set of "trust anchors"—the root certificates of CAs that you rely on. 
            * These should be protected from tampering, 
            * so that an attacker doesn't replace a CA certificate with his own fake. 
            * The public keys in these certificates are used to verify the digital signatures on other certificates.
        A collection of Intermediate certificates. 
        * The application might keep a collection of these, but most protocols, like SSL and S/MIME, that use certificates have a standard way to provide extra certificates. Storing these doesn't require any special care; their integrity is protected by the signature of a root CA.
        Revocation information. Even if a certificate was issued by a CA, i
        * t might have been revoked prematurely because the private key was disclosed, 
        * or the end entity changed their identity. (For example, a person switches jobs and a certificate with their old company's name in it is revoked.) 
        * CRLs or a web-service like OCSP can be used to get an update about the status of a certificate
         * 
         */
        //see here for how to do crl / ocsp etc
        //http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
       // http://en.wikipedia.org/wiki/Trust_anchor
        
        //documentCertificate.
        
        return false;
    }
    public byte[][] getSodHashes ()  {
        return sodHashes;
    }

    final static boolean debugMode = false;

    public void refresh() throws CardException, IOException, PteidException {

        
        byte[] sod = pteid.ReadSOD();

        int k = 4;

        byte[] newSod = new byte[sod.length - k];
        System.arraycopy(sod, k, newSod, 0, sod.length - k);

        PKCS7 p7 = new PKCS7(newSod);

        X509Certificate[] certificates = p7.getCertificates();
        
        AlgorithmId[] digestAlgorithmIds = p7.getDigestAlgorithmIds();
 
        if (debugMode) {
            System.out.println("P7 get Version: " + p7.getVersion().toString());
            System.out.println("Dump Object\n" + p7.toString());
            //using bouncycastle to dump the object
            //ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(dataBytes));
            //ASN1Object obj2 = (ASN1Object) bIn.readObject();
            //System.out.println(ASN1Dump.dumpAsString(obj2, true));
            System.out.println("certificates (devia ser 1)" + certificates.length);
            System.out.println("certificates[0] subject DN " + certificates[0].getSubjectDN());

            try {
                int certLength = certificates[0].getEncoded().length;
                System.out.println("certificates[0] len " + certLength);
            } catch (CertificateEncodingException ex) {
                Logger.getLogger(ReleasePteid_Validate.class.getName()).log(Level.SEVERE, null, ex);
            }


            for (int i = 0; i < digestAlgorithmIds.length; i++) {
                System.out.println("Digest Algorithms ids: " + digestAlgorithmIds[i].getName());
            }
        }

        //Verifications for Cartão de Cidadão (CC)
        if ( certificates.length != 1 || digestAlgorithmIds.length !=1 || !digestAlgorithmIds[0].getName().equals("SHA256"))
            throw new CardException("SOD Verifiy Error");
        
        documentCertificate = certificates[0];
        
        ContentInfo contentInfo = p7.getContentInfo();
        DerValue content = contentInfo.getContent();
        byte[] dataBytes = content.getDataBytes();
        if (debugMode) {
            System.out.println("Content Info: " + contentInfo.toString());
            System.out.println("Content Length=" + dataBytes.length);
            System.out.println(ReleaseUtils.bytesToHex(dataBytes));
        }
        
        //Create Hash of the data block containg the four hashes
        String hashAlgorithm = "SHA-256";
        MessageDigest sha256Instance=null; 
        try {
            sha256Instance = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ReleasePteid_Validate.class.getName()).log(Level.SEVERE, null, ex);
            throw new CardException("SOD Verify Error: Crypto"+ex.getMessage());  
        }
        byte[] fourHashDataDigest = sha256Instance.digest(dataBytes);
        if (debugMode) {
            System.out.println("   fourHashDataDigest: " + ReleaseUtils.bytesToHex(fourHashDataDigest));
        }

        //extract the hash from the signed data section of the PKCS 7 structure
        SignerInfo[] signerInfos = p7.getSignerInfos();

        PKCS9Attributes authenticatedAttributes = signerInfos[0].getAuthenticatedAttributes();
        PKCS9Attribute[] attributes = authenticatedAttributes.getAttributes();

        //pkcs 9 structure extract digest sha256 32 bytes
        byte [] fourHashDataDigestSOD = (byte[]) attributes[1].getValue();
        if (debugMode) {
            System.out.println("fourHashDataDigestSOD: " + ReleaseUtils.bytesToHex(fourHashDataDigestSOD));
        }
       
        if ( ! Arrays.equals(fourHashDataDigestSOD, fourHashDataDigest)  )
               throw new CardException("SOD Verifiy Error : Hashes do Not Validate");
       
        
        //ghet the signature
        byte[] signature = signerInfos[0].getEncryptedDigest();
        
        //decrypt the signature
        Cipher cipher;
        byte[] cipherData=null;
        byte [] extractedHash=null;
        try {
            cipher = Cipher.getInstance("RSA");
            PublicKey publicKey = certificates[0].getPublicKey();
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            cipherData = cipher.doFinal(signature);
             if (debugMode) System.out.println("decipher :" + ReleaseUtils.bytesToHex(cipherData));
            extractedHash = new byte[32];
            System.arraycopy(cipherData, cipherData.length-32,extractedHash , 0, 32);
        } catch (Exception ex) {
            Logger.getLogger(ReleasePteid_Validate.class.getName()).log(Level.SEVERE, null, ex);
            throw new CardException("SOD Verify Error: Crypto" + ex.getMessage());
        }

        //Hash the signed data block in order to verify decrypted signature
        //for complete checking use bouncycastle
        //no time to write a proper parser ..leave for later
        //System.out.println("der encoding..note no checking of certificate validity ocsp/crl etc");
        byte[] signedDataDigest = null;
        
        //the length of the bytes should be 256;
        signedDataDigest = sha256Instance.digest(authenticatedAttributes.getDerEncoding());
         if (debugMode) System.out.println("signedDataDigest"+ ReleaseUtils.bytesToHex(signedDataDigest) );

        //extract the hah from this ANS.1 Der structure .. the last 32 bytes
        //should also check the OIDs etc
        
        //compare the hashes
        if ( ! Arrays.equals(signedDataDigest, extractedHash)  )
               throw new CardException("SOD Verifiy Error : Hashes do Not Validate");
 
        
        //verified !!!!!!!!!!!!!!!!!!!
        
        extractHashes(dataBytes);

        // must be at least 3 hashes (header, module info, & whole file)
        if (sodHashes.length < 4) {
            throw new CardException("too few hashes in signed data");
        }
        
        if (debugMode) 
            for (int i=0;i<4;i++)
                System.out.println("Hash: "+i+" :"+ReleaseUtils.bytesToHex(sodHashes[i]));
        
    }



    public boolean check(Pteid_Person obj) throws CardException, IOException {
        if ( Arrays.equals( sodHashes[0], obj.getDigest() ) )
        { 
            return true;
        } 
        return false;
    }

    public boolean check(Pteid_Address obj) {
         if ( Arrays.equals( sodHashes[1], obj.getDigest() ) )
        { 
            return true;
        } 
        return false;
    }

    public boolean check(Pteid_Pic obj)  {       
        if ( Arrays.equals( sodHashes[2], obj.getDigest() ) )
        { 
            return true;
        } 
        return false;
    }

    public boolean checkPk_Icc_Aut(Pteid_Person obj)  {
        if ( Arrays.equals( sodHashes[3], obj.getDigestPK_ICC_AUT() ) )
        {
            return true;
        } 
        return false;
    }

    private void extractHashes(byte content[]) {
        //sequence 30 13 6 09 9data plus NULL
        //This is ANS sequence identifier followed by the 9 byte =ID for SHA 256 then followed by null 
        byte[] sha256Oid = {
            (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
            (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x01,
            (byte) 0x05, (byte) 0x00};

        byte[] ANSnull = {(byte) 0x05, (byte) 0x00};
        byte ANSseq = (byte) 0x30;
        byte ANSinteger = (byte) 0x02;  //2 bytes follows 
        byte ANSoctectstring = (byte) 04; //length follows 32

        byte byteLengthQualifier;
        byte byteLength;

        //check data is correct length
        if (content[0] == ANSseq) {
            byteLength = content[1];
            if (byteLength > (byte) 0x80) {
                byteLength = content[2];
            }
            int len = (int) byteLength & 0xff;
            len = len + 3;
            if (len != content.length) {
                sodHashes = null;
            }
        } else {
            sodHashes = null;
        }

        //1 Find sha256 Oid in byte array                           
        int index = ReleaseUtils.indexOf(content, sha256Oid);
        if (index == -1) {
            sodHashes = null;
        }

        index = index + sha256Oid.length;

        if (content[index++] != ANSseq) {
            sodHashes = null;
        }
        byteLengthQualifier = content[index++];
        byteLength = content[index++];

        if ((byteLength & 0xff) != (content.length - index)) {
            sodHashes = null;
        }

        sodHashes = new byte[4][32];

        for (int i = 0; i < 4; i++) {
            //will simply parse the entir block altering the offset when necessary
            byte[] SequenceIntegerOctet = {ANSseq, (byte) 0x25, ANSinteger, (byte) 0x01, (byte) (0x01 + i), ANSoctectstring, (byte) 0x20};
            if (checkHeader(content, index, SequenceIntegerOctet) == false) {
                sodHashes = null;
            }
            index = index + SequenceIntegerOctet.length;
            System.arraycopy(content, index, sodHashes[i], 0, 32);
            // System.out.println("Hash:"+ToHex(hashes[i]));
            index = index + 32;
        }

        //return hashes;
    }

    private boolean checkHeader(byte[] content, int startIndex, byte[] header) {
        if (header.length > content.length - startIndex) {
            return false;
        }
        for (int i = 0; i < header.length; i++) {
            if (content[startIndex + i] != header[i]) {
                return false;
            }
        }
        return true;
    }
}
