import javax.swing.*;
import java.awt.*;

public class KeyGeneratorMain {

    public static void main(String args[]) throws Exception {
        JFrame frame = new JFrame("RSA Key Generator");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        GridBagLayout layout = new GridBagLayout();
        frame.setLayout(layout);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0, 0, 0, 10);
        frame.setSize(640,480);

        new PinForm(frame, gbc);

        frame.setVisible(true);
    }
}
