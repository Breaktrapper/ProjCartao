/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package release.ubi.pt;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

/**
 *
 * @author Paul Crocker
 */
public class ReleaseUtils {

    //LICENSE=0 --> all parts of mware
    //LICENSE=1 --> without the object library
    
   //protected final static int LICENSE=1;
   protected final static int LICENSE=0;
    
    public static String bytesToHex(byte[] bytes, int len) {
        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        char[] hexChars = new char[len * 3];
        int v;
        for (int j = 0; j < len; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 3] = hexArray[v >>> 4];
            hexChars[j * 3 + 1] = hexArray[v & 0x0F];
            hexChars[j * 3 + 2] = ' ';
        }
        return new String(hexChars);
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        char[] hexChars = new char[bytes.length * 3];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 3] = hexArray[v >>> 4];
            hexChars[j * 3 + 1] = hexArray[v & 0x0F];
            hexChars[j * 3 + 2] = ' ';
        }
        return new String(hexChars);
    }

    /// <summary>
    /// Encoding information to UTF8
    /// </summary>
    public static String stringFromCard(byte[] data, int offset) {

        int i = 0;
        String outputX;
        //find the next zero
        while ((int) data[i + offset] != 0 && i < data.length) {
            i++;
        }
        try {
            //String(byte[] bytes, int offset, int length, String charsetName) 
            //Constructs a new String by decoding the specified subarray of bytes using the specified charset.
            outputX = new String(data, offset, i, "UTF-8");
        } catch (Exception e) {
            outputX = "Exception" + e.getMessage();
        }
        return outputX;
    }
     public static String stringFromCardFixedLength(byte[] data, int offset, int iLength) {

         //For Istance the Back Part Machine Readable is a fixed 90 byte length
        String outputX;
        try {
            //String(byte[] bytes, int offset, int length, String charsetName) 
            //Constructs a new String by decoding the specified subarray of bytes using the specified charset.
            outputX = new String(data, offset, iLength, "UTF-8");
        } catch (Exception e) {
            outputX = "Exception" + e.getMessage();
        }
        return outputX;
    }
     
     /* 
     * Knuth-Morris-Pratt Algorithm for Pattern Matching
     * Implementation based on avove refs
     * Finds the first occurrence of the pattern in the text.
     * this is kmp .. maybe a bit exagerated but in general its quick
      see my sedgewick book for implementation
      http://en.wikipedia.org/wiki/Knuth%E2%80%93Morris%E2%80%93Pratt_algorithm
      http://stackoverflow.com/questions/1507780/searching-for-a-sequence-of-bytes-in-a-binary-file-with-java     
     */
    static public int indexOf(byte[] data, byte[] pattern) {
        int[] failure = computeFailure(pattern);

        int j = 0;
        if (data.length == 0) return -1;

        for (int i = 0; i < data.length; i++) {
            while (j > 0 && pattern[j] != data[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == data[i]) { j++; }
            if (j == pattern.length) {
                return i - pattern.length + 1;
            }
        }
        return -1;
    }

    /**
     * Computes the failure function using a boot-strapping process,
     * where the pattern is matched against itself.
     */
    static private int[] computeFailure(byte[] pattern) {
        int[] failure = new int[pattern.length];

        int j = 0;
        for (int i = 1; i < pattern.length; i++) {
            while (j > 0 && pattern[j] != pattern[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == pattern[i]) {
                j++;
            }
            failure[i] = j;
        }

        return failure;
    } 
    
    static public String GetCardReaderDefault() { 
        TerminalFactory factory;
        CardTerminals terminals;
        List<CardTerminal> lista = null;
        factory = TerminalFactory.getDefault();
        terminals = factory.terminals();

        try {
            lista = terminals.list(CardTerminals.State.ALL);
            for (CardTerminal terminal : lista){
                 if ( terminal.isCardPresent()  )
                     return terminal.getName();
            }
            /* If No Card is Present return the First CardReader*/
            return lista.get(0).getName();
                 
        } catch (CardException ex) {
            return "No Card Reader Found";
        }
    }
    
    /* Get a list of all the Card Readers */
    static public List<CardTerminal> getCardReaders(CardTerminals.State state) throws CardException
    {
        TerminalFactory factory;
        CardTerminals terminals;
        List<CardTerminal> lista = null;
       
        factory = TerminalFactory.getDefault();
        terminals = factory.terminals();

        lista = terminals.list(state);
        return lista;       
    }
    
    /* Return the CardReader given a users choice. Note a crda must be present */
    static public CardTerminal getCardTerminal(String name) throws CardException
    {
        TerminalFactory factory;
        CardTerminals terminals;
        List<CardTerminal> lista = null;
       
        factory = TerminalFactory.getDefault();
        terminals = factory.terminals();

        lista = terminals.list(CardTerminals.State.CARD_PRESENT);
        
       String[] readers = new String[lista.size()];
           
        for (CardTerminal terminal : lista){
             
           if (terminal.getName().equals(name))
                   return terminal;
        }
        throw new CardException("User Choosen Card Reader Not Found");
    }
    
}
