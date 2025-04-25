import javax.swing.*;
import java.awt.*;
import com.formdev.flatlaf.FlatDarculaLaf;

class Main{
    public static void main(String args[]){
        try {
            UIManager.setLookAndFeel(new FlatDarculaLaf());
        } catch (Exception ex) {
            System.err.println("Failed to initialize LaF");
        }

        JFrame frame = new JFrame("PDF Encryption App");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        GridBagLayout layout = new GridBagLayout();
        frame.setLayout(layout);
        GridBagConstraints gbc = new GridBagConstraints();
        frame.setSize(720,480);

        gbc.insets = new Insets(0, 10, 0, 0);
        FileSelectorForm fileForm = new FileSelectorForm(frame, gbc);
        new FileSigningManager(frame, gbc, fileForm);
        gbc.weighty = 0.1;
        new KeysCheck(frame, gbc);

        frame.setVisible(true);
    }
}