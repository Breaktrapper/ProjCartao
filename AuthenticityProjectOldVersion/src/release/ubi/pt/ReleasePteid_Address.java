/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package release.ubi.pt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import release.ubi.pt.ReleaseUtils;

/**
 *
 * @authorPaul Crocker For lengths see eidlib.h eidlibcard.cpp
 */
public class ReleasePteid_Address {

    private final int PTEID_ADDR_TYPE_LEN = 2;
    private final int PTEID_ADDR_COUNTRY_LEN = 4;
    private final int PTEID_DISTRICT_LEN = 4;
    private final int PTEID_DISTRICT_DESC_LEN = 100;
    private final int PTEID_DISTRICT_CON_LEN = 8;
    private final int PTEID_DISTRICT_CON_DESC_LEN = 100;
    private final int PTEID_DISTRICT_FREG_LEN = 12;
    private final int PTEID_DISTRICT_FREG_DESC_LEN = 100;
    private final int PTEID_ROAD_ABBR_LEN = 20;
    private final int PTEID_ROAD_LEN = 100;
    private final int PTEID_ROAD_DESIG_LEN = 200;
    private final int PTEID_HOUSE_ABBR_LEN = 20;
    private final int PTEID_HOUSE_LEN = 100;
    private final int PTEID_NUMDOOR_LEN = 20;
    private final int PTEID_FLOOR_LEN = 40;
    private final int PTEID_SIDE_LEN = 40;
    private final int PTEID_PLACE_LEN = 100;
    private final int PTEID_LOCALITY_LEN = 100;
    private final int PTEID_CP4_LEN = 8;
    private final int PTEID_CP3_LEN = 6;
    private final int PTEID_POSTAL_LEN = 50;
    private final int PTEID_NUMMOR_LEN = 12;
    private final int PTEID_ADDR_COUNTRYF_DESC_LEN = 100;
    private final int PTEID_ADDRF_LEN = 300;
    private final int PTEID_CITYF_LEN = 100;
    private final int PTEID_REGIOF_LEN = 100;
    private final int PTEID_LOCALITYF_LEN = 100;
    private final int PTEID_POSTALF_LEN = 100;
    private final int PTEID_NUMMORF_LEN = 12;

    private final Field[] fields = ReleasePteid_Address.class.getDeclaredFields();

    public int getNrFields() {
        return fields.length;
    }
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

    public ReleasePteid_Address() {
    }

    public void parse(byte[] data) throws IOException {
        if (data == null || data.length < 1146) {
            return;
        }
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();

        int tot = 0;
        this.addrType = ReleaseUtils.stringFromCard(data, tot);
        tot += PTEID_ADDR_TYPE_LEN;

        if ("N".equals(this.addrType)) {
            this.country = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_ADDR_COUNTRY_LEN;
            byteOut.write(country.getBytes());

            this.district = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_DISTRICT_LEN;
            byteOut.write(district.getBytes());

            this.districtDesc = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_DISTRICT_DESC_LEN;
            byteOut.write(districtDesc.getBytes());

            this.municipality = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_DISTRICT_CON_LEN;
            byteOut.write(municipality.getBytes());

            this.municipalityDesc = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_DISTRICT_CON_DESC_LEN;
            byteOut.write(municipalityDesc.getBytes());

            this.freguesia = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_DISTRICT_FREG_LEN;
            byteOut.write(freguesia.getBytes());

            this.freguesiaDesc = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_DISTRICT_FREG_DESC_LEN;
            byteOut.write(freguesiaDesc.getBytes());

            this.streettypeAbbr = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_ROAD_ABBR_LEN;
            byteOut.write(streettypeAbbr.getBytes());

            this.streettype = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_ROAD_LEN;
            byteOut.write(streettype.getBytes());

            this.street = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_ROAD_DESIG_LEN;
            byteOut.write(street.getBytes());

            this.buildingAbbr = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_HOUSE_ABBR_LEN;
            byteOut.write(buildingAbbr.getBytes());

            this.building = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_HOUSE_LEN;
            byteOut.write(building.getBytes());

            this.door = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_NUMDOOR_LEN;
            byteOut.write(door.getBytes());

            this.floor = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_FLOOR_LEN;
            byteOut.write(floor.getBytes());

            this.side = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_SIDE_LEN;
            byteOut.write(side.getBytes());

            this.place = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_PLACE_LEN;
            byteOut.write(place.getBytes());

            this.locality = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_LOCALITY_LEN;
            byteOut.write(locality.getBytes());

            this.cp4 = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_CP4_LEN;
            byteOut.write(cp4.getBytes());

            this.cp3 = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_CP3_LEN;
            byteOut.write(cp3.getBytes());

            this.postal = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_POSTAL_LEN;
            byteOut.write(postal.getBytes());

            this.numMor = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_NUMMOR_LEN;
            byteOut.write(numMor.getBytes());
        } else {
            //foreign address not checked
            this.countryDescF = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_ADDR_COUNTRYF_DESC_LEN;
            this.addressF = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_ADDRF_LEN;
            this.cityF = this.addressF = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_CITYF_LEN;
            this.regioF = this.addressF = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_REGIOF_LEN;
            this.localityF = this.addressF = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_LOCALITYF_LEN;
            this.postalF = this.addressF = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_POSTALF_LEN;
            this.numMorF = ReleaseUtils.stringFromCard(data, tot);
            tot += PTEID_NUMMORF_LEN;
        }
        //System.out.println("Total=" + tot);

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
            //System.out.println("Morada (1146) length+" + dataSodCheck.length + "\nHash:"+ ReleaseUtils.bytesToHex(digest));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ReleasePteid_Address.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * Common Code to Person Object
     */
    public void print() {
        for (int i = 0; i < fields.length; i++) {
            String name = fields[i].getName();
            if (name.equals("fields") || name.contains("PTEID") || name.equals("digest")) {
                continue;
            }
            try {
                String value = (String) fields[i].get(this);
                System.out.printf("%s=%s\n", name, value);
            } catch (IllegalAccessException ex) {
                Logger.getLogger(ReleasePteid_Person.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalArgumentException ex) {
                Logger.getLogger(ReleasePteid_Person.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public String getField(int i) {
        String name = fields[i].getName();
        if (name.equals("fields") || name.equals("digest")) {
            return "";
        }
        try {
            String value = name + "=" + (String) fields[i].get(this);
            return value;
        } catch (Exception ex) {
            return ("ERROR i=" + i + " name=" + name + " " + ex.getMessage());
        }
    }

    public String getField(String fieldName) {
        for (int i = 0; i < fields.length; i++) {
            String name = fields[i].getName();
            if (name.equals("fields") || name.equals("digest")) {
                continue;
            }
            try {
                String value = (String) fields[i].get(this);
                return value;
            } catch (Exception ex) {
                return ("ERROR" + ex.getMessage());
            }
        }
        return ("Field Not Found");
    }
}
