package AppPackage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.security.cert.X509Certificate;
import pt.gov.cartaodecidadao.PTEID_ByteArray;
import pteidlib.PTEID_ADDR;

import pteidlib.PTEID_Certif;
import pteidlib.PTEID_ID;
import pteidlib.PTEID_PIC;
import pteidlib.PteidException;
import pteidlib.pteid;

import release.ubi.pt.ReleasePteid_Address;
import release.ubi.pt.ReleasePteid_Person;
import release.ubi.pt.ReleasePteid_Pic;

/**
 * @author João Saraiva - FEITO COM A VERSÃO ANTIGA DO MIDDLEWARE DO GOVERNO
 */
public class Apiexample {

    private byte[] ID_Digest;
    private byte[] ADDR_Digest;
    private byte[] PIC_Digest;

    //Load system library..
    static {
        try {
            System.loadLibrary("pteidlibj");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }
    }

    public static byte[] getAddress(PTEID_ADDR address) throws PteidException, IOException {

        byte[] addressData = null;

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        byteOut.write(address.addrType.getBytes());
        byteOut.write(address.country.getBytes());
        byteOut.write(address.district.getBytes());
        byteOut.write(address.districtDesc.getBytes());
        byteOut.write(address.municipality.getBytes());
        byteOut.write(address.municipalityDesc.getBytes());
        byteOut.write(address.freguesia.getBytes());
        byteOut.write(address.freguesiaDesc.getBytes());
        byteOut.write(address.streettypeAbbr.getBytes());
        byteOut.write(address.street.getBytes());
        byteOut.write(address.buildingAbbr.getBytes());
        byteOut.write(address.building.getBytes());
        byteOut.write(address.door.getBytes());
        byteOut.write(address.floor.getBytes());
        byteOut.write(address.side.getBytes());
        byteOut.write(address.place.getBytes());
        byteOut.write(address.locality.getBytes());
        byteOut.write(address.cp4.getBytes());
        byteOut.write(address.cp3.getBytes());
        byteOut.write(address.postal.getBytes());
        byteOut.write(address.numMor.getBytes());
        byteOut.write(address.countryDescF.getBytes());
        byteOut.write(address.addressF.getBytes());
        byteOut.write(address.cityF.getBytes());
        byteOut.write(address.regioF.getBytes());
        byteOut.write(address.localityF.getBytes());
        byteOut.write(address.postalF.getBytes());
        byteOut.write(address.numMorF.getBytes());

        addressData = byteOut.toByteArray();
        return addressData;
    }

    public static byte[] getID(PTEID_ID id) throws PteidException, IOException {

        byte[] idData = null;

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        byteOut.write(id.deliveryEntity.getBytes());
        byteOut.write(id.country.getBytes());
        byteOut.write(id.documentType.getBytes());
        byteOut.write(id.cardNumber.getBytes());
        byteOut.write(id.cardNumberPAN.getBytes());
        byteOut.write(id.cardVersion.getBytes());
        byteOut.write(id.deliveryDate.getBytes());
        byteOut.write(id.locale.getBytes());
        byteOut.write(id.validityDate.getBytes());
        byteOut.write(id.name.getBytes());
        byteOut.write(id.firstname.getBytes());
        byteOut.write(id.sex.getBytes());
        byteOut.write(id.nationality.getBytes());
        byteOut.write(id.birthDate.getBytes());
        byteOut.write(id.height.getBytes());
        byteOut.write(id.numBI.getBytes());
        byteOut.write(id.nameFather.getBytes());
        byteOut.write(id.firstnameFather.getBytes());
        byteOut.write(id.firstnameMother.getBytes());
        byteOut.write(id.numNIF.getBytes());
        byteOut.write(id.numSS.getBytes());
        byteOut.write(id.numSNS.getBytes());
        byteOut.write(id.notes.getBytes());

        idData = byteOut.toByteArray();
        return idData;
    }

    public static byte[] getPIC(PTEID_PIC pic) throws PteidException, IOException {

        byte[] picData = null;

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        byteOut.write(pic.cbeff);
        byteOut.write(pic.facialinfo);
        byteOut.write(pic.facialrechdr);
        byteOut.write(pic.imageinfo);
        byteOut.write(pic.picture);

        picData = byteOut.toByteArray();
        return picData;
    }

    public static void main(String[] args) throws IOException {

        try {
            //Inicilize card
            pteid.Init("");
            pteid.SetSODChecking(false);
            /*
            System.out.println("//--- Leitura do ficheiro SOD ---//\n");
            byte[] sodFile = pteid.ReadSOD();
            helperFile.saveSOD(sodFile, "sodFile.der");
            
            System.out.println("//--- Certificados digitais ---//\n");

            PTEID_Certif[] certs = pteid.GetCertificates();
            System.out.println("Encontrados " + certs.length + " certificados!");
            X509Certificate x509 = X509Certificate.getInstance(certs[0].certif);
            System.out.println("\nCertificado " + 0 + ":" + "\nDN do Certificado: " + x509.getSubjectDN() + "\nDN do Emissor" + x509.getIssuerDN() + "\nValido até: " + x509.getNotAfter());
            helperFile.saveCerts(x509);
            
            for (int i = 0; i < certs.length; i++) {

                X509Certificate x509 = X509Certificate.getInstance(certs[i].certif);

                System.out.println("\nCertificado " + i + ":" + "\nDN do Certificado: " + x509.getSubjectDN() + "\nDN do Emissor" + x509.getIssuerDN() + "\nValido até: " + x509.getNotAfter());
                helperFile.saveCerts(x509);
            }
             */
 /*
            //DIGEST FROM CARD ADDRESS
            PTEID_ADDR addressData = pteid.GetAddr();
            byte[] byteArray = getAddress(addressData);
            ReleasePteid_Address pteid_address = new ReleasePteid_Address();
            pteid_address.parse(byteArray);
            byte[] addressDigest = pteid_address.getDigest();
            System.out.println("Address Digest: " + addressDigest.toString());
   
            
            PTEID_PIC picData = pteid.GetPic();
            if (picData != null) 
            {
                byte[] byteArray3 = getPIC(picData);
                ReleasePteid_Pic pteid_pic = new ReleasePteid_Pic();
                pteid_pic.parse(byteArray3);
                byte[] personDigest = pteid_pic.getDigest();
                System.out.println("Pic Digest: " + personDigest.toString());
            }
             */
            //DIGEST FROM CARD ID
            
            PTEID_ID idData = pteid.GetID();
            if (idData != null) 
            {
                byte[] byteArray2 = getID(idData);
                ReleasePteid_Person pteid_id = new ReleasePteid_Person();
                pteid_id.parse(byteArray2);
                byte[] personDigest = pteid_id.getDigest();
                String hex = release.ubi.pt.ReleaseUtils.bytesToHex(personDigest);
                System.out.println(hex);
                
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
