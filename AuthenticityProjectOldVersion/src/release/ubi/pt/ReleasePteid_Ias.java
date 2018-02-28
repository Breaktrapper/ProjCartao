/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package release.ubi.pt;

import java.io.IOException;

/**
 *
 * @author TOSHIBA
 */
public class ReleasePteid_Ias {
    
    public ReleasePteid_Person pessoa;
    public ReleasePteid_Pic    foto;
    
    public ReleasePteid_Ias(byte [] data) throws IOException
    {
        pessoa = new  ReleasePteid_Person();
        pessoa.parse(data);
        
        foto = new ReleasePteid_Pic ();
        foto.parsePic(data, 256*6);
    }
    
}
