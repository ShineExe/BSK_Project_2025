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
        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel inputLabel = new JLabel("Text to encrypt:");
        inputLabel.setFont(new Font("Verdana", Font.BOLD, 14));
        frame.add(inputLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = 2;
        JTextField inputField = new JTextField(10);
        frame.add(inputField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel pinLabel = new JLabel("Enter PIN:");
        pinLabel.setFont(new Font("Verdana", Font.BOLD, 14));
        frame.add(pinLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = 3;
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
        gbc.gridy = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JButton encryptButton = new JButton("ENCRYPT");
        frame.add(encryptButton, gbc);

        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 3;
        JLabel hashLabel = new JLabel("");
        hashLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(hashLabel, gbc);

        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 3;
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
                SignatureManager sm = new SignatureManager();
                try {
                    publicKey = Files.readAllBytes(Paths.get("keys/public_key.txt"));
                    privateKey = Files.readAllBytes(Paths.get("keys/private_key.txt"));

                    String pin = String.valueOf(pinField.getPassword());
                    byte[] hash = inputField.getText().getBytes(StandardCharsets.UTF_8);
                    encryptedLabel.setText("Hash: " + new String(hash));
                    byte[] encrypted = sm.encryptHash(hash, privateKey, pin);
                    encryptedLabel.setText("Encrypted: " + new String(encrypted).substring(0,10) + "...");
                    byte[] decryptedHash = sm.decryptHash(encrypted, publicKey);
                    decryptedLabel.setText("Decrypted: " +  new String(decryptedHash));

                    byte[] comparisonHash = inputField.getText().getBytes(StandardCharsets.UTF_8);
                    resultLabel.setText("IsHashCorrect: " + Arrays.equals(hash, comparisonHash));

                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });
    }
}
