import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Set;

/**
 * \ingroup MainApp
 * \brief Class responsible for searching the drives for a stored private key
 * \details The class compares list of previously detected drives with the currently available ones.
 * If a new external drive is found, method tries to locate and save the private key file.
 */
public class ExternalDriveSearcher {
    private byte[] foundKey = null;
    private String keyName = "private_key.txt";
    private Set<String> knownDrives;

    public ExternalDriveSearcher(Set<String> knownDrives) {
        File[] roots = File.listRoots(); // all available drives
        this.knownDrives = knownDrives;

        for (File root : roots) {
            String path = root.getAbsolutePath();

            if (!knownDrives.contains(path) && root.canRead()) {
                System.out.println("Drive found: " + path);
                knownDrives.add(path);

                // search for the encrypted key file on the new drive
                File keyFile = new File(root, keyName);
                if (keyFile.exists()) {
                    try {
                        this.foundKey = Files.readAllBytes(keyFile.toPath());
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        System.out.println("Failed to read key file");
                    }
                }
            }
        }

        // remove missing drives
        knownDrives.removeIf(path -> Arrays.stream(File.listRoots())
                .noneMatch(f -> f.getAbsolutePath().equals(path)));
    }

    public byte[] getKeyFromDrive() {
        return foundKey;
    }
}
