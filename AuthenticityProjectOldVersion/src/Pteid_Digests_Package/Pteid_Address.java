/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Pteid_Digests_Package;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import pteidlib.PTEID_ADDR;
import release.ubi.pt.ReleasePteid_Address;
import release.ubi.pt.ReleaseUtils;

/**
 *
 * @author jonas
 */
public class Pteid_Address {

    //private final Field[] fields = Pteid_Address.class.getDeclaredFields(); --> Qual a utilidade?
    public String addressF;
    public String addrType;
    public String building;
    public String buildingAbbr;
    public String cityF;
    public String country;
    public String countryDescF;
    public String cp3;
    public String cp4;
    public String district;
    public String districtDesc;
    public String floor;
    public String door;
    public String freguesia;
    public String freguesiaDesc;
    public String locality;
    public String localityF;
    public String municipality;
    public String municipalityDesc;
    public String numMor;
    public String numMorF;
    public String place;
    public String postal;
    public String postalF;
    public String regioF;
    public String side;
    public String street;
    public String streettype;
    public String streettypeAbbr;

    private byte[] digest;

    public byte[] getDigest() {
        return digest;
    }

    public Pteid_Address() {
    }

    public void parse_address(PTEID_ADDR address) throws IOException {

        if (address == null) {
            System.out.println("Objeto vazio..");
            return;
        }
        this.addrType = address.addrType;
        this.addressF = address.addressF;
        this.building = address.building;
        this.buildingAbbr = address.buildingAbbr;
        this.cityF = address.cityF;
        this.country = address.country;
        this.countryDescF = address.countryDescF;
        this.cp3 = address.cp3;
        this.cp4 = address.cp4;
        this.district = address.district;
        this.districtDesc = address.districtDesc;
        this.door = address.door;
        this.floor = address.floor;
        this.freguesia = address.freguesia;
        this.freguesiaDesc = address.freguesiaDesc;
        this.locality = address.locality;
        this.localityF = address.localityF;
        this.municipality = address.municipality;
        this.municipalityDesc = address.municipalityDesc;
        this.numMor = address.numMor;
        this.numMorF = address.numMorF;
        this.place = address.place;
        this.postal = address.postalF;
        this.postalF = address.postalF;
        this.regioF = address.regioF;
        this.side = address.side;
        this.street = address.street;
        this.streettype = address.streettype;
        this.streettypeAbbr = address.streettypeAbbr;

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        byteOut.write(this.addrType.getBytes());
        byteOut.write(this.addressF.getBytes());
        byteOut.write(this.building.getBytes());
        byteOut.write(this.buildingAbbr.getBytes());
        byteOut.write(this.cityF.getBytes());
        byteOut.write(this.country.getBytes());
        byteOut.write(this.countryDescF.getBytes());
        byteOut.write(this.cp3.getBytes());
        byteOut.write(this.cp4.getBytes());
        byteOut.write(this.district.getBytes());
        byteOut.write(this.districtDesc.getBytes());
        byteOut.write(this.door.getBytes());
        byteOut.write(this.floor.getBytes());
        byteOut.write(this.freguesia.getBytes());
        byteOut.write(this.freguesiaDesc.getBytes());
        byteOut.write(this.locality.getBytes());
        byteOut.write(this.localityF.getBytes());
        byteOut.write(this.municipality.getBytes());
        byteOut.write(this.municipalityDesc.getBytes());
        byteOut.write(this.numMor.getBytes());
        byteOut.write(this.numMorF.getBytes());
        byteOut.write(this.place.getBytes());
        byteOut.write(this.postal.getBytes());
        byteOut.write(this.postalF.getBytes());
        byteOut.write(this.regioF.getBytes());
        byteOut.write(this.side.getBytes());
        byteOut.write(this.street.getBytes());
        byteOut.write(this.streettype.getBytes());
        byteOut.write(this.streettypeAbbr.getBytes());

        setDigest(byteOut.toByteArray());
    }

    /* Set the Digest for SOD Check
     * 
     */
    private void setDigest(byte dataSodCheck[]) {
        String hashAlgorithm = "SHA-256";
        MessageDigest sha1; // Compute digest
        try {
            sha1 = MessageDigest.getInstance(hashAlgorithm);
            digest = sha1.digest(dataSodCheck);
            System.out.println("Morada (1146) length+" + dataSodCheck.length + "\nHash: " + ReleaseUtils.bytesToHex(digest));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Pteid_Address.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
