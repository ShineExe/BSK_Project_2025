import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class KeysCheck {
    private byte[] publicKey;
    private byte[] privateKey;

    public KeysCheck(JFrame frame, GridBagConstraints gbc){
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel inputLabel = new JLabel("Text to encrypt:");
        inputLabel.setFont(new Font("Verdana", Font.BOLD, 14));
        frame.add(inputLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        JTextField inputField = new JTextField(10);
        frame.add(inputField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 1;
        JLabel pinLabel = new JLabel("Enter PIN:");
        pinLabel.setFont(new Font("Verdana", Font.BOLD, 14));
        frame.add(pinLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 1;
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
        gbc.gridy = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JButton encryptButton = new JButton("ENCRYPT TEXT");
        frame.add(encryptButton, gbc);

        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 3;
        JLabel messageLabel = new JLabel("");
        messageLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(messageLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = 5;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel encryptedLabel = new JLabel("");
        encryptedLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(encryptedLabel, gbc);

        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 3;
        JLabel decryptedLabel = new JLabel("");
        decryptedLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(decryptedLabel, gbc);

        gbc.gridx = 0;
        gbc.gridy = 7;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 3;
        JLabel resultLabel = new JLabel("");
        resultLabel.setFont(new Font("Verdana", Font.BOLD, 10));
        frame.add(resultLabel, gbc);

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                KeyManager km = new KeyManager();
                messageLabel.setText("");
                encryptedLabel.setText("");
                decryptedLabel.setText("");
                resultLabel.setText("");
                try {
                    publicKey = Files.readAllBytes(Paths.get("keys/public_key.txt"));
                    privateKey = Files.readAllBytes(Paths.get("keys/private_key.txt"));

                    String pin = String.valueOf(pinField.getPassword());
                    byte[] message = inputField.getText().getBytes(StandardCharsets.UTF_8);
                    messageLabel.setText("Input: " + new String(message));
                    byte[] decryptedPrivateKey = null;
                    try {
                        decryptedPrivateKey = km.decryptPrivateKey(privateKey, pin);
                    } catch (Exception keyException) {
                        resultLabel.setText("PrivateKey Decryption Failed, check entered PIN");
                        return;
                    }
                    byte[] encrypted = km.encryptHash(message, decryptedPrivateKey);
                    encryptedLabel.setText("Encrypted: " + new String(encrypted).substring(0,10) + "... +" + encrypted.length);
                    byte[] decrypted = km.decryptHash(encrypted, publicKey);
                    decryptedLabel.setText("Decrypted: " +  new String(decrypted));

                    resultLabel.setText("IsDecryptionCorrect: " + Arrays.equals(message, decrypted));

                } catch (Exception ex) {
                    ex.printStackTrace();
                    resultLabel.setText("Decryption Failed");
                }
            }
        });
    }
}
