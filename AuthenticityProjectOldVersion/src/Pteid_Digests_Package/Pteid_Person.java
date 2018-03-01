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
import java.lang.reflect.Field;

import pteidlib.PTEID_ID;
import pteidlib.PTEID_RSAPublicKey;
import pteidlib.PteidException;
import release.ubi.pt.ReleaseUtils;

/**
 *
 * @author jonas
 */
public class Pteid_Person {

    //private final Field[] fields = Pteid_Person.class.getDeclaredFields(); --> qual a utilidade?
    private String EntidadeEmissora;
    private String País;
    private String TipoDocumento;
    //private String NumeroDocumento; Não existe..
    private String PAN;
    private String VersaoCartao;
    private String DataEmissao;
    private String LocalPedido;
    private String DataValidade;
    //private String Apelido; Não existe..
    private String Nome;
    private String Sexo;
    private String Nacionalidade;
    private String DataNascimento;
    private String Altura;
    private String NBi;
    //private String ApelidoMae; Não existe..
    private String NomeProprioMae;
    //private String ApelidoPai; Não existe..
    private String NomeProprioPai;
    private String NFiscal;
    private String NSegSocial;
    private String NSaude;
    private String IndicacoesEventuais;
    //private String ID_CC_Tras; Não existe..

    private byte[] PK_ICC_AUT;
    //private String PICEB; ??

    private byte[] digest;
    private byte[] digestPK_ICC_AUT;

    public byte[] getDigestPK_ICC_AUT() {
        return digestPK_ICC_AUT;
    }

    public byte[] getDigest() {
        return digest;
    }

    public byte[] getPK_ICC_AUT() {
        return PK_ICC_AUT;
    }

    //Construtor vazio
    public Pteid_Person() {
    }

    public void parse_Person(PTEID_ID id) throws PteidException, IOException {

        if (id == null) {
            System.out.println("Objeto vazio..");
            return;
        }
        this.Altura = id.height;
        this.DataEmissao = id.deliveryDate;
        this.DataNascimento = id.birthDate;
        this.DataValidade = id.validityDate;
        this.EntidadeEmissora = id.deliveryEntity;
        this.IndicacoesEventuais = id.notes;
        this.LocalPedido = id.locale;
        this.NBi = id.numBI;
        this.NFiscal = id.numNIF;
        this.NSaude = id.numSNS;
        this.NSegSocial = id.numSS;
        this.Nacionalidade = id.nationality;
        this.Nome = id.name;
        this.NomeProprioMae = id.nameMother;
        this.NomeProprioPai = id.nameFather;
        this.PAN = id.cardNumberPAN;
        this.País = id.country;
        this.Sexo = id.sex;
        this.TipoDocumento = id.documentType;
        this.VersaoCartao = id.cardVersion;

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        byteOut.write(this.Altura.getBytes());
        byteOut.write(this.DataEmissao.getBytes());
        byteOut.write(this.DataNascimento.getBytes());
        byteOut.write(this.DataValidade.getBytes());
        byteOut.write(this.EntidadeEmissora.getBytes());
        byteOut.write(this.IndicacoesEventuais.getBytes());
        byteOut.write(this.LocalPedido.getBytes());
        byteOut.write(this.NBi.getBytes());
        byteOut.write(this.NFiscal.getBytes());
        byteOut.write(this.NSaude.getBytes());
        byteOut.write(this.NSegSocial.getBytes());
        byteOut.write(this.Nacionalidade.getBytes());
        byteOut.write(this.Nome.getBytes());
        byteOut.write(this.NomeProprioMae.getBytes());
        byteOut.write(this.NomeProprioPai.getBytes());
        byteOut.write(this.PAN.getBytes());
        byteOut.write(this.País.getBytes());
        byteOut.write(this.Sexo.getBytes());
        byteOut.write(this.TipoDocumento.getBytes());
        byteOut.write(this.VersaoCartao.getBytes());

        setDigest(byteOut.toByteArray());
    }

    public void parse_Person_Key(PTEID_RSAPublicKey key) throws IOException {

        if (key == null) {
            System.out.println("Objeto vazio..");
            return;
        }
        this.PK_ICC_AUT = key.modulus;

        setDigest(PK_ICC_AUT);
        digestPK_ICC_AUT = digest;

    }

    private void setDigest(byte dataSodCheck[]) {
        String hashAlgorithm = "SHA-256";
        MessageDigest sha1; // Compute digest
        try {
            sha1 = MessageDigest.getInstance(hashAlgorithm);
            digest = sha1.digest(dataSodCheck);
            System.out.println("ID (1372) length+" + dataSodCheck.length + "\nHash: " + ReleaseUtils.bytesToHex(digest));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Pteid_Person.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
