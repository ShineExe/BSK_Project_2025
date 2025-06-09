import javax.swing.*;
import java.awt.*;
import com.formdev.flatlaf.FlatDarculaLaf;

/** \defgroup MainApp Main application
 * \brief Responsible for .pdf file signing
 */

/**
 * \ingroup MainApp
 * \brief Main class for the file signing app.
 * \details Initializes the main app window and creates its needed components.
 * App has two modes - simple one (raw hash) or advanced (where signature with proper CMS structure gets generated).
 */
class Main{

    /**
     * \brief defines file sigining mode
     * \details if set to true - the generated signature is embedding the raw encrypted hash into the PDF file,
     * if set to false - signature is generated using proper CMS structure via BouncyCastle.
     */
    private static boolean simpleMode = false;

    public static void main(String args[]){
        // initializing UI Look and Feel
        try {
            UIManager.setLookAndFeel(new FlatDarculaLaf());
        } catch (Exception ex) {
            System.err.println("Failed to initialize LaF");
        }

        // initializing main app window
        JFrame frame = new JFrame("PDF Encryption App");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        GridBagLayout layout = new GridBagLayout();
        frame.setLayout(layout);
        GridBagConstraints gbc = new GridBagConstraints();
        frame.setSize(960,480);
        gbc.insets = new Insets(0, 10, 0, 0);

        // initializing main app components
        FileSelectorForm fileForm = new FileSelectorForm(frame, gbc);
        new FileSigningManager(frame, gbc, fileForm, simpleMode);
        new VerificationManager(frame, gbc, fileForm, simpleMode);

        frame.setVisible(true);
    }
}