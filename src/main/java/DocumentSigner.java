import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * \ingroup MainApp
 * \brief Class responsible signing the document with provided signature.
 */
public class DocumentSigner {
    private PDDocument document;
    private PDSignature signature;
    private byte[] privKeyBytes;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private boolean mode;


    /**
     * \brief DocumentSigner class constructor.
     */
    public DocumentSigner(PDDocument document, byte[] privKeyBytes, PublicKey publicKey, PrivateKey privateKey, boolean mode) {
        this.document = document;
        this.privKeyBytes = privKeyBytes;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.mode = mode;
        this.signature = new PDSignature();
    }

    /**
     * \brief Method adds a PAdES compatible signature to the file
     * \details The signature is added with the use of provided private key.
     * Document hash is generated using SHA-256. Document is signed with a created self-signed certificate.
     */
    public PDDocument signDocument() throws IOException {
        try {
            createSignature();
        } catch (Exception e) {
            throw new IOException("Failed to prepare signature", e);
        }

        // adding signature logic
        document.addSignature(signature, content -> {
            try {
                byte[] contentBytes = content.readAllBytes();
                KeyManager km = new KeyManager();

                // generate document hash (SHA-256)
                byte[] hash = km.getDocumentHash(contentBytes);

                byte[] signatureBytes = null;
                if (mode) {
                    // simple mode - just sign the hash using private key
                    signatureBytes = km.encryptHash(hash, privKeyBytes);
                } else {
                    // complex mode - generating CMS-based signature

                    // generating and embedding the self-signed certificate
                    X509Certificate cert = generateSelfSignedCert();

                    // build CMS for proper PAdES signature
                    CMSTypedData msg = new CMSProcessableByteArray(contentBytes);
                    List<X509Certificate> certList = List.of(cert);
                    Store<?> certs = new JcaCertStore(certList);

                    // sign and encrypt using private key
                    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                    ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA")
                            .setProvider("BC").build(privateKey);

                    gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                            .build(sha256Signer, cert));
                    gen.addCertificates(certs);

                    CMSSignedData signedData = gen.generate(msg, false);

                    signatureBytes = signedData.getEncoded();
                }

                return signatureBytes;

            } catch (Exception ex) {
                throw new IOException("Signing error", ex);
            }
        });
        return document;
    }

    /**
     * \brief Method creates a signature.
     * \details Signature takes current local time.
     */
    private void createSignature() throws Exception {
        // signature metadata
        signature.setSignDate(Calendar.getInstance());
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("User A");
        signature.setLocation("Gdansk University of Technology");
        signature.setReason("Signature generated for Security of Computer Systems project");
    }

    /**
     * \brief Method creates a self-signed certificate.
     * \details Certificate is created with current system time, signed with a private key.
     */
    private X509Certificate generateSelfSignedCert() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String issuer = "CN=UserA, O=PG";
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        Date creationDate = new Date(System.currentTimeMillis());  // local time when signed
        Date expirationDate = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365);  // valid 1 year from now

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuer),
                serial,
                creationDate,
                expirationDate,
                new X500Principal(issuer),
                publicKey
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));
    }
}
