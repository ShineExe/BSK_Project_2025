import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

/**
 * \ingroup MainApp
 * \brief Class responsible for choosing the .pdf file
 * \details Creates and manages the file selection form part of the UI.
 */
public class FileSelectorForm {
    private File file;

    /**
     * \brief Method returns the previously selected file.
     */
    public File getFile() {
        return file;
    }

    /**
     * \brief FileSelectorForm class initialization, layout and main actions setup.
     * \details Creates the part of UI responsible for selecting a .pdf file and handles the user interactions.
     */
    public FileSelectorForm(JFrame frame, GridBagConstraints gbc) {
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weighty = 0.25;
        JLabel selectLabel = new JLabel("Select .pdf file to encrypt or verify");
        selectLabel.setFont(new Font("Verdana", Font.BOLD, 14));
        frame.add(selectLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = 0;
        JButton selectButton = new JButton("Select file");
        frame.add(selectButton, gbc);

        gbc.gridx = 2;
        gbc.gridy = 0;
        JLabel sentFileLabel = new JLabel("");
        sentFileLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(sentFileLabel, gbc);

        // button was clicked - handling file selection
        selectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                FileFilter filter = new FileNameExtensionFilter("PDF Documents", "pdf");
                fileChooser.setFileFilter(filter);
                int response = fileChooser.showOpenDialog(null);
                if (response == JFileChooser.APPROVE_OPTION) {
                    String fileName = fileChooser.getSelectedFile().getName();
                    String fileExtension = fileName.substring(fileName.length()-3);

                    if (fileExtension.equals("pdf")) {
                        file = new File(fileChooser.getSelectedFile().getAbsolutePath());
                        sentFileLabel.setText(fileName);
                    }
                    else { sentFileLabel.setText("Wrong filetype (only .pdf accepted)"); }
                }
            }
        });
    }
}
