import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

class Main{
    public static void main(String args[]){
        JFrame frame = new JFrame("PDF Encryption App");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new FlowLayout());
        frame.setSize(640,480);

        JLabel selectLabel = new JLabel("Send .pdf file to encrypt");
        selectLabel.setFont(new Font("Verdana", Font.BOLD, 14));
        frame.add(selectLabel);

        JButton selectButton = new JButton("Select file");
        //selectButton.setBounds(260, 220, 120, 40);
        frame.add(selectButton);

        JLabel sentFileLabel = new JLabel("");
        sentFileLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(sentFileLabel);

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
                        File file = new File(fileChooser.getSelectedFile().getAbsolutePath());
                        sentFileLabel.setText(fileName);
                    }
                    else { sentFileLabel.setText("Wrong filetype (only .pdf accepted)"); }
                }
            }
        });

        frame.setVisible(true);
    }
}