import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

/**
 * \ingroup MainApp
 * \brief Class responsible signing the document with provided signature.
 */
public class DocumentSigner {
    private PDDocument document;
    private PDSignature signature;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private X509Certificate cert;

    /**
     * \brief DocumentSigner class constructor.
     */
    public DocumentSigner(PDDocument document, PDSignature signature, PrivateKey privateKey, PublicKey publicKey) {
        this.document = document;
        this.signature = signature;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * \brief Method adds a PAdES compatible signature to the file
     * \details The signature is added with the use of provided private key.
     * Document hash is generated using SHA-256. Document is signed with a created self-signed certificate.
     */
    public PDDocument signDocument() throws IOException {
        document.addSignature(signature, content -> {
            // Use CMS + RSA
            try {
                BouncyCastleProvider provider = new BouncyCastleProvider();
                Security.addProvider(provider);

                byte[] contentBytes = content.readAllBytes();

                // generate document hash (SHA-256)
                byte[] hash = new KeyManager().getDocumentHash(contentBytes);

                CMSProcessableByteArray msg = new CMSProcessableByteArray(hash);
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

                ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC")
                        .build(privateKey);

                cert = generateSelfSignedCert();

                gen.addSignerInfoGenerator(
                        new JcaSignerInfoGeneratorBuilder(
                                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
                        ).build(signer, cert)
                );

                gen.addCertificates(new JcaCertStore(Collections.singletonList(cert)));

                CMSSignedData sigData = gen.generate(msg, false);
                return sigData.getEncoded();
            } catch (Exception ex) {
                ex.printStackTrace();
                throw new IOException("Signing failed: " + ex.getMessage(), ex);
            }
        });

        return document;
    }

    /**
     * \brief Method creates a self-signed certificate.
     * \details Certificate is created with current system time, signed with private key.
     */
    private X509Certificate generateSelfSignedCert() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String issuer = "CN=UserA, O=PolitechnikaGdanska";
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);  // 1h ago
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365);  // valid 1 year

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuer),
                serial,
                notBefore,
                notAfter,
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
