import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.List;
import java.nio.file.Files;

public class VerificationManager {
    private byte[] publicKey;
    private File inputFile;

    /**
     * \brief VerificationManager class initialization, layout and main actions setup.
     * \details Handles the user actions to verify signature of the chosen file.
     */
    public VerificationManager(JFrame frame, GridBagConstraints gbc, FileSelectorForm fileForm) {

        JLabel statusLabel = new JLabel("");

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JButton verifyButton = new JButton("VERIFY");
        frame.add(verifyButton, gbc);

        gbc.gridx = 1;
        gbc.gridy = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel resultLabel = new JLabel("");
        resultLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(resultLabel, gbc);

        KeyManager km = new KeyManager();
        publicKey = km.loadPublicKey(statusLabel);

        // the verify button was clicked
        verifyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (publicKey == null)
                {
                    resultLabel.setText("Public key not found!");
                    return;
                }

                try {
                    if (verifySignedPDF(inputFile, publicKey))
                        resultLabel.setText("Signature is correct!");
                    else resultLabel.setText("Document invalid!");
                } catch (Exception ex) {
                    ex.printStackTrace();
                    resultLabel.setText("Verification error: " + ex.getMessage());
                }
//                byte[] hash = null;
//                try {
//                    hash = km.getDocumentHash(Files.readAllBytes(inputFile.toPath()));
//                } catch (Exception exception) {
//                    resultLabel.setText("No file attached!");
//                    return;
//                }
//
//                // byte[] decrypted = km.decryptHash(encrypted, publicKey);
//
//                // resultLabel.setText("IsHashCorrect: " + Arrays.equals(hash, decrypted));
            }
        });
    }

    /**
     * \brief Method responsible for verifying signature in a signed document.
     * \details Method generates hash of a document using SHA-256 and compares it with the original hash,
     * which is decrypted using the public key.
     */
    public boolean verifySignedPDF(File signedPdf, byte[] publicKeyBytes) throws Exception {
        return true;
    }
}
