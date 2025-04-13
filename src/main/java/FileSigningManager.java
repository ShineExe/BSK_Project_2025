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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FileSigningManager {
    private byte[] publicKey;
    private byte[] privateKey;
    private File inputFile;
    private boolean keysCorrect;

    private void loadKeys(JLabel statusLabel) {
        keysCorrect = true;
        statusLabel.setText(statusLabel.getText() + "PublicKey:loaded");
        try {
            publicKey = Files.readAllBytes(Paths.get("keys/public_key.txt"));
        } catch (NullPointerException | IOException fileException) {
            statusLabel.setText("Public key not found!");
            keysCorrect = false;
        }

        try {
            privateKey = Files.readAllBytes(Paths.get("keys/private_key.txt"));
        } catch (NullPointerException | IOException fileException) {
            statusLabel.setText(statusLabel.getText() + ", Private key not found!");
            keysCorrect = false;
            return;
        }
        statusLabel.setText(statusLabel.getText() + ", PrivateKey:loaded");
    }

    public FileSigningManager(JFrame frame, GridBagConstraints gbc, FileSelectorForm fileForm) {
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 4;
        gbc.weighty = 0.1;
        JLabel statusLabel = new JLabel("");
        statusLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(statusLabel, gbc);

        loadKeys(statusLabel);
        String keyStatus = statusLabel.getText();

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
