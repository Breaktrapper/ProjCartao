/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package apiexample;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/**
 *
 * @author jonas
 */
public class Apiexample {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws CardException {
        // show the list of available terminals
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        System.out.println("Terminals: " + terminals);
        // get the first terminal
        CardTerminal terminal = terminals.get(0);
        // establish a connection with the card
        Card card = terminal.connect("T=0");
        System.out.println("card: " + card);
        CardChannel channel = card.getBasicChannel();
        byte[] c1 = null;
        ResponseAPDU r = channel.transmit(new CommandAPDU(c1));
        System.out.println("response: " + toString(r.getBytes()));
        // disconnect
        card.disconnect(false);
    }

    private static String toString(byte[] bytes) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
