import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PinForm extends JFrame{

    public PinForm(JFrame frame, GridBagConstraints gbc){
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel pinLabel = new JLabel("Enter PIN:");
        pinLabel.setFont(new Font("Verdana", Font.BOLD, 14));
        frame.add(pinLabel, gbc);

        gbc.gridx = 1;
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
        JButton pinButton = new JButton("OK");
        frame.add(pinButton);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 3;
        JLabel sentPinLabel = new JLabel("");
        sentPinLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        frame.add(sentPinLabel, gbc);

        pinButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String sentPin = String.valueOf(pinField.getPassword());
                if (sentPin.length() >= 4) {
                    sentPinLabel.setText(sentPin);
                    System.out.println("PIN:" + sentPin);
                    try {
                        RSAKeysFromPIN genKeys = new RSAKeysFromPIN(sentPin);
                        sentPinLabel.setText(genKeys.getFeedbackMessage());
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
                else sentPinLabel.setText("PIN too short (min. 4 digits)");
            }
        });
    }
}
