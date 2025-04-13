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
        GridBagLayout layout = new GridBagLayout();
        frame.setLayout(layout);
        GridBagConstraints gbc = new GridBagConstraints();
        frame.setSize(640,480);

        gbc.insets = new Insets(0, 0, 0, 10);
        gbc.weighty = 0.25;
        new FileSelectorForm(frame, gbc);
        gbc.weighty = 0.1;
        new KeysCheck(frame, gbc);

        frame.setVisible(true);
    }
}