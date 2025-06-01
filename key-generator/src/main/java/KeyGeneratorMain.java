import javax.swing.*;
import java.awt.*;
import com.formdev.flatlaf.FlatDarculaLaf;

/**
 * \brief Main class for the key-generator component.
 * \details Initializes the main app window and creates its needed components.
 */
public class KeyGeneratorMain {

    public static void main(String args[]) throws Exception {
        try {
            UIManager.setLookAndFeel(new FlatDarculaLaf());
        } catch (Exception ex) {
            System.err.println("Failed to initialize LaF");
        }

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
