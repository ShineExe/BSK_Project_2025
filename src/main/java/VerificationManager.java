import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class VerificationManager {
    private byte[] publicKey;
    private KeyManager km;
    private File inputFile;
    private final int signatureSize = 512;

    /**
     * \brief VerificationManager class initialization, layout and main actions setup.
     * \details Handles the user actions to verify signature of the chosen file.
     */
    public VerificationManager(JFrame frame, GridBagConstraints gbc, FileSelectorForm fileForm, boolean simpleMode) {
        km = new KeyManager();
        JLabel statusLabel = new JLabel("");

        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JButton verifyButton = new JButton("VERIFY");
        frame.add(verifyButton, gbc);

        gbc.gridx = 1;
        gbc.gridy = 5;
        JButton modifyButton = new JButton("MODIFY PDF");
        frame.add(modifyButton, gbc);

        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 4;
        JLabel resultLabel = new JLabel("");
        resultLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(resultLabel, gbc);

        // the verify button was clicked
        verifyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                publicKey = km.loadPublicKey(statusLabel);
                if (publicKey == null)
                {
                    resultLabel.setText("Public key not found!");
                    return;
                }

                try {
                    inputFile = fileForm.getFile();
                    if (inputFile == null) {
                        resultLabel.setText("No file attached!");
                        return;
                    }

                    boolean verificationResult;

                    // choosing verification method based on mode
                    if (simpleMode) verificationResult = verifySignedPDF(inputFile);
                    else verificationResult = verifySignedWithCMS(inputFile);

                    if (verificationResult)
                        resultLabel.setText("Signature correct.");
                    else resultLabel.setText("Document signature invalid!");

                } catch (Exception ex) {
                    ex.printStackTrace();
                    resultLabel.setText("Verification error: " + ex.getMessage());
                }
            }
        });

        // the modify button was clicked
        modifyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modifyFile(resultLabel);
            }
        });
    }

    /**
     * \brief Method responsible for verifying a simple signature in a signed document.
     * \details Method generates hash of a document using SHA-256 and compares it with the original hash,
     * which is decrypted using the public key.
     */
    public boolean verifySignedPDF(File signedPdf) throws Exception {
        try (PDDocument doc = PDDocument.load(signedPdf)) {
            List<PDSignature> signatures = doc.getSignatureDictionaries();
            if (signatures.isEmpty()) {
                throw new Exception("No signatures found in document.");
            }
            PDSignature sig = signatures.get(0);

            // generating hash of the signed content using SHA-256
            byte[] signedContent = sig.getSignedContent(new FileInputStream(signedPdf));
            byte[] expectedHash = km.getDocumentHash(signedContent);

            // extracting the original raw hash from padded signature
            COSDictionary sigDict = sig.getCOSObject();
            COSString contents = (COSString) sigDict.getDictionaryObject("Contents");
            if (contents == null) {
                throw new Exception("No signature content found.");
            }
            byte[] paddedSignatureBytes = contents.getBytes();
            byte[] signatureHash = Arrays.copyOf(paddedSignatureBytes, signatureSize);

            // decrypting the original hash using the public key
            byte[] decryptedHash = km.decryptHash(signatureHash, publicKey);

            return Arrays.equals(expectedHash, decryptedHash);
        }
    }


    /**
     * \brief Method responsible for advanced verifying CMS-based signatures.
     * \details Method uses BouncyCastle's CMSSignedData to load and verify the signature created in advanced mode.
     */
    public boolean verifySignedWithCMS(File signedPdf) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try (PDDocument document = PDDocument.load(signedPdf)) {
            List<PDSignature> signatureList = document.getSignatureDictionaries();
            if (signatureList.isEmpty()) {
                throw new Exception("No CMS signatures found.");
            }

            // extracting CMS 'Contents' from signature dictionary
            PDSignature signature = signatureList.get(0);
            COSString contents = (COSString) signature.getCOSObject().getDictionaryObject("Contents");
            if (contents == null) {
                throw new Exception("No Contents in signature.");
            }

            byte[] cmsSignature = contents.getBytes();
            byte[] signedContent = signature.getSignedContent(new FileInputStream(signedPdf));

            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signedContent), cmsSignature);

            // retrieving signer information
            SignerInformationStore signerStore = cms.getSignerInfos();
            Collection<SignerInformation> signers = signerStore.getSigners();
            if (signers.isEmpty()) {
                throw new Exception("No signers found.");
            }
            SignerInformation signer = signers.iterator().next();

            // extracting and matching certificate for signer
            Store<X509CertificateHolder> certStore = cms.getCertificates();
            Collection<X509CertificateHolder> certCollection = certStore.getMatches(signer.getSID());
            if (certCollection.isEmpty()) {
                throw new Exception("No matching certificate found.");
            }

            // getting the certificate from extracted holder
            X509CertificateHolder certHolder = certCollection.iterator().next();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(certHolder.getEncoded()));

            // verifying  the CMS signature
            try {
                return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert));
            } catch (org.bouncycastle.cms.CMSSignerDigestMismatchException e) {
                // signature invalid - the file has been tampered with
                return false;
            }
        }
    }

    /**
     * \brief Method modifies the selected file and overwrites it.
     * To showcase resistance to modification, the file is being modified
     * (in this simple example the document title is being changed).
     */
    private void modifyFile(JLabel resultLabel) {
        try (PDDocument doc = PDDocument.load(inputFile)) {
            // simple title change to mark modification
            doc.getDocumentInformation().setTitle("File_was_manipulated");
            doc.save(inputFile.getName()); // overwriting the file
            resultLabel.setText("File was modified.");
        } catch (IOException e) {
            e.printStackTrace();
            resultLabel.setText("Error: File modification failed!");
        }
    }
}
