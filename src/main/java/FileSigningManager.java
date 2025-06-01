import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * \brief Class responsible for the main app functionality and layout
 * \details The class manages loading the needed file and keys and handles the user interface,
 * allowing to sign and check the signature for the chosen document.
 */
public class FileSigningManager {
    private byte[] publicKey;
    private byte[] privateKey;
    private File inputFile;
    private boolean keysCorrect = false;

    /**
     * \brief Method responsible for loading the public key from memory
     * \details The method checks the 'keys' folder for the file created by the key-generator component.
     * The set status informs of the action result.
     */
    private void loadPublicKey(JLabel statusLabel) {
        statusLabel.setText("PublicKey:loaded");
        try {
            publicKey = Files.readAllBytes(Paths.get("keys/public_key.txt"));
        } catch (NullPointerException | IOException fileException) {
            statusLabel.setText("PublicKey:missing!");
        }
    }

    /**
     * \brief Method responsible for loading the private key from an external drive
     * \details The method checks every 5 seconds if private key was found.
     * If not, it checks through ExternalDriveSearcher if any new drives are present,
     * and calls the method to get the keys from them.
     */
    private void loadPrivateKey(JLabel statusLabel) {
        Set<String> knownDrives = new HashSet<>();
        String prevStatus = statusLabel.getText();

        // check for key in drives every 5 seconds
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            if (privateKey==null) {
                keysCorrect = false;
                statusLabel.setText(prevStatus + ", PrivateKey:missing!");
                ExternalDriveSearcher eds = new ExternalDriveSearcher(knownDrives);
                privateKey = eds.getKeyFromDrive();
            }
            else {
                if (!keysCorrect && publicKey!=null) {
                    statusLabel.setText(prevStatus + ", PrivateKey:loaded");
                    keysCorrect = true;
                }
            }
        }, 0, 5, TimeUnit.SECONDS);
    }

    /**
     * \brief FileSigningManager class initialization, layout and main actions setup.
     * \details Creates main app gui, handles the user actions to sign the file
     * that has been chosen through FileSelectorForm.
     */
    public FileSigningManager(JFrame frame, GridBagConstraints gbc, FileSelectorForm fileForm) {
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 4;
        gbc.weighty = 0.1;
        JLabel statusLabel = new JLabel("");
        statusLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(statusLabel, gbc);

        loadPublicKey(statusLabel);
        loadPrivateKey(statusLabel);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weighty = 0.5;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel pinLabel = new JLabel("Enter PIN:");
        pinLabel.setFont(new Font("Verdana", Font.BOLD, 14));
        frame.add(pinLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JPasswordField pinField = new JPasswordField(4);
        frame.add(pinField, gbc);

        ((AbstractDocument)pinField.getDocument()).setDocumentFilter(new DocumentFilter(){
            Pattern regEx = Pattern.compile("\\d*");
            @Override
            public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException, BadLocationException {
                Matcher matcher = regEx.matcher(text);
                if(!matcher.matches()){
                    return;
                }
                super.replace(fb, offset, length, text, attrs);
            }
        });

        gbc.gridx = 2;
        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JButton signButton = new JButton("SIGN");
        frame.add(signButton, gbc);

        gbc.gridx = 3;
        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel resultLabel = new JLabel("");
        resultLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(resultLabel, gbc);

        signButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                KeyManager km = new KeyManager();
                String keyStatus = statusLabel.getText();
                if (!keysCorrect) resultLabel.setText("Key not found!");
                else try {
                    inputFile = fileForm.getFile();
                    byte[] hash = null;
                    try {
                        hash = km.getInputHash(Files.readAllBytes(inputFile.toPath()));
                    } catch (NullPointerException fileException) {
                        resultLabel.setText("No file attached!");
                        return;
                    }

                    String pin = String.valueOf(pinField.getPassword());
                    byte[] decryptedPrivateKey = null;
                    try {
                        decryptedPrivateKey = km.decryptPrivateKey(privateKey, pin);
                    } catch (Exception keyException) {
                        resultLabel.setText("Incorrect PIN!");
                        statusLabel.setText(keyStatus + ", PrivateKey Decryption: failed");
                        return;
                    }
                    statusLabel.setText(keyStatus + ", PrivateKey Decryption: successful");

                    byte[] encrypted = km.encryptHash(hash, decryptedPrivateKey);
                    byte[] decrypted = km.decryptHash(encrypted, publicKey);

                    resultLabel.setText("IsHashCorrect: " + Arrays.equals(hash, decrypted));

                } catch (Exception ex) {
                    ex.printStackTrace();
                    resultLabel.setText(ex.getMessage());
                }
            }
        });
    }
}
