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
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Paul Crocker
 */
public class ReleasePteid_Person {

    private final Field[] fields = ReleasePteid_Person.class.getDeclaredFields();
    private String EntidadeEmissora;
    private String País;
    private String TipoDocumento;
    private String NumeroDocumento;
    private String PAN;
    private String VersaoCartao;
    private String DataEmissao;
    private String LocalPedido;
    private String DataValidade;
    private String Apelido;
    private String Nome;
    private String Sexo;
    private String Nacionalidade;
    private String DataNascimento;
    private String Altura;
    private String NBi;
    private String ApelidoMae;
    private String NomeProprioMae;
    private String ApelidoPai;
    private String NomeProprioPai;
    private String NFiscal;
    private String NSegSocial;
    private String NSaude;
    private String IndicacoesEventuais;
    private String ID_CC_Tras;
    
    
    private String PICEB;
    
    private byte[] PK_ICC_AUT;
    private byte[] digest;
    
    private byte[] digestPK_ICC_AUT;

    public byte[] getDigestPK_ICC_AUT() {
        return digestPK_ICC_AUT;
    }

    public byte[] getDigest() {
        return digest;
    }

    public int getNrFields() {
        return fields.length;
    }

    public String getNBi() {
        return NBi;
    }
    
    public String getAltura() {
        return Altura;
    }

    public String getApelido() {
        return Apelido;
    }

    public String getDataEmissao() {
        return DataEmissao;
    }

    public String getDataNascimento() {
        return DataNascimento;
    }

    public String getEntidadeEmissora() {
        return EntidadeEmissora;
    }

    public String getApelidoPai() {
        return ApelidoPai;
    }

    public String getApelidoMae() {
        return ApelidoMae;
    }

    public String getNomeProprioMae() {
        return NomeProprioMae;
    }

    public String getNomeProprioPai() {
        return NomeProprioPai;
    }

    public String getID_CC_Tras() {
        return ID_CC_Tras;
    }

    public String getLocalPedido() {
        return LocalPedido;
    }

    public String getNFiscal() {
        return NFiscal;
    }

    public String getNSaude() {
        return NSaude;
    }

    public String getNSegSocial() {
        return NSegSocial;
    }

    public String getNacionalidade() {
        return Nacionalidade;
    }

    public String getNome() {
        return Nome;
    }

    public String getNumeroDocumento() {
        return NumeroDocumento;
    }

    public String getPaís() {
        return País;
    }

    public void setPaís(String País) {
        this.País = País;
    }

    public String getSexo() {
        return Sexo;
    }

    public String getTipoDocumento() {
        return TipoDocumento;
    }

    public String getVersaoCartao() {
        return VersaoCartao;
    }

    public String getDataValidade() {
        return DataValidade;
    }

    public String getPAN() {
        return PAN;
    }

    public String getPICEB() {
        return PICEB;
    }

    public byte[] getPK_ICC_AUT() {
        return PK_ICC_AUT;
    }

    public String getIndicacoesEventuais() {
        return IndicacoesEventuais;
    }

    
    public void parse(byte[] data) throws IOException {
        if (data == null || data.length < 1536) {
            return;
        }

        EntidadeEmissora = ReleaseUtils.stringFromCard(data, 0);
        País = ReleaseUtils.stringFromCard(data, 40);
        TipoDocumento = ReleaseUtils.stringFromCard(data, 120);
        NumeroDocumento = ReleaseUtils.stringFromCard(data, 154);
        PAN = ReleaseUtils.stringFromCard(data, 182);
        VersaoCartao = ReleaseUtils.stringFromCard(data, 214);
        DataEmissao = ReleaseUtils.stringFromCard(data, 230);
        LocalPedido = ReleaseUtils.stringFromCard(data, 250);
        DataValidade = ReleaseUtils.stringFromCard(data, 310);
        Apelido = ReleaseUtils.stringFromCard(data, 330);
        Nome = ReleaseUtils.stringFromCard(data, 450);
        Sexo = ReleaseUtils.stringFromCard(data, 570);
        Nacionalidade = ReleaseUtils.stringFromCard(data, 572);
        DataNascimento = ReleaseUtils.stringFromCard(data, 578);
        Altura = ReleaseUtils.stringFromCard(data, 598);
        NBi = ReleaseUtils.stringFromCard(data, 606);
        ApelidoMae = ReleaseUtils.stringFromCard(data, 624);
        NomeProprioMae = ReleaseUtils.stringFromCard(data, 744);
        ApelidoPai = ReleaseUtils.stringFromCard(data, 864);
        NomeProprioPai = ReleaseUtils.stringFromCard(data, 984);
        NFiscal = ReleaseUtils.stringFromCard(data, 1104);
        NSegSocial = ReleaseUtils.stringFromCard(data, 1122);
        NSaude = ReleaseUtils.stringFromCard(data, 1144);
        IndicacoesEventuais = ReleaseUtils.stringFromCard(data, 1162);
        ID_CC_Tras = ReleaseUtils.stringFromCardFixedLength(data, 1282, 90);
        //EXTRAS see CC Documentation
        
        PK_ICC_AUT = new byte[131];
        System.arraycopy(data, 1372, PK_ICC_AUT, 0, 131);
        
        //PK_ICC_AUT = ReleaseUtils.stringFromCardFixedLength(data, 1372, 131);
        //PICEB = ReleaseUtils.stringFromCardFixedLength(data, 1503, 33);

        //Data is thus 1282+90 = 1372 = 256*5.3
        //need to read 6 blocs
        //1536 =  256 *6

        //EF_ID = 15500 Bytes
        //ID Data is 1503
        //Picture Data is 15500 - 1503 = 13997
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        byteOut.write(EntidadeEmissora.getBytes());
        byteOut.write(País.getBytes());
        byteOut.write(TipoDocumento.getBytes());
        byteOut.write(NumeroDocumento.getBytes());
        byteOut.write(PAN.getBytes());
        byteOut.write(VersaoCartao.getBytes());
        byteOut.write(DataEmissao.getBytes());
        byteOut.write(LocalPedido.getBytes());
        byteOut.write(DataValidade.getBytes());
        byteOut.write(Apelido.getBytes());
        byteOut.write(Nome.getBytes());
        byteOut.write(Sexo.getBytes());
        byteOut.write(Nacionalidade.getBytes());
        byteOut.write(DataNascimento.getBytes());
        byteOut.write(Altura.getBytes());
        byteOut.write(NBi.getBytes());
        byteOut.write(ApelidoMae.getBytes());
        byteOut.write(NomeProprioMae.getBytes());
        byteOut.write(ApelidoPai.getBytes());
        byteOut.write(NomeProprioPai.getBytes());
        byteOut.write(IndicacoesEventuais.getBytes());
        byteOut.write(NFiscal.getBytes());
        byteOut.write(NSegSocial.getBytes());
        byteOut.write(NSaude.getBytes());
        
        setDigest(PK_ICC_AUT);
        digestPK_ICC_AUT = digest;
        
        setDigest(byteOut.toByteArray());
    }

    private void setDigest(byte dataSodCheck[]) {
        String hashAlgorithm = "SHA-256";
        MessageDigest sha1; // Compute digest
        try {
            sha1 = MessageDigest.getInstance(hashAlgorithm);
            digest = sha1.digest(dataSodCheck);
            System.out.println("ID (1372) length+" + dataSodCheck.length + "\nHash:" + ReleaseUtils.bytesToHex(digest));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ReleasePteid_Address.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void print() {
        System.out.printf("Field name: %s, Field value: %s%n", "Nome", Nome);
        System.out.printf("Field name: %s, Field value: %s%n", "Apelido", Apelido);
        for (int i = 0; i < fields.length; i++) {
            String name = fields[i].getName();
            if (name.equals("fields") || name.equals("digest") || name.equals("PK_ICC_AUT")
                    || name.equals("digestPK_ICC_AUT")) {
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
