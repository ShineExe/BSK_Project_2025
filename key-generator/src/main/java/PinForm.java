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

/**
 * \ingroup KeyGen
 * \brief Class responsible for key-generator UI management
 * \details Creates and manages the PIN entering form and handles user's actions to generate an RSA key pair.
 */
public class PinForm extends JFrame{
    /**
     * \brief PinForm class initialization, layout and main actions setup.
     * \details Creates the part of UI responsible for creating a new PIN and keys.
     */
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

        // ensuring that the PIN field takes only number values
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

        gbc.insets = new Insets(10,0, 0, 0);
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JProgressBar progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        frame.add(progressBar, gbc);

        gbc.gridy = 3;
        JLabel genFeedbackLabel = new JLabel("");
        genFeedbackLabel.setFont(new Font("Verdana", Font.PLAIN, 10));
        genFeedbackLabel.setHorizontalAlignment(JLabel.CENTER);
        frame.add(genFeedbackLabel, gbc);

        // button submitting the entered pin was clicked
        pinButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String sentPin = String.valueOf(pinField.getPassword());
                if (sentPin.length() < 4) {
                    genFeedbackLabel.setText("PIN too short (min. 4 digits)");
                    return;
                }
                else {
                    pinButton.setEnabled(false);
                    genFeedbackLabel.setText("Generating keys...");
                    progressBar.setValue(0);
                    progressBar.setVisible(true);
                    System.out.println("PIN: " + sentPin);

                    SwingWorker<String, Void> worker = new SwingWorker<>() {
                        @Override
                        protected String doInBackground() throws Exception {
                            RSAKeysFromPIN genKeys = new RSAKeysFromPIN(sentPin, this::setProgress);
                            return genKeys.getFeedbackMessage();
                        }

                        @Override
                        protected void done() {
                            try {
                                String result = get();
                                genFeedbackLabel.setText(result);
                                pinButton.setEnabled(true);
                            } catch (Exception ex) {
                                ex.printStackTrace();
                                genFeedbackLabel.setText("Key generation failed");
                            }
                            pinField.setText("");
                        }
                    };
                    worker.addPropertyChangeListener(evt -> {
                        if ("progress".equals(evt.getPropertyName())) {
                            int progress = (int) evt.getNewValue();
                            progressBar.setValue(progress);
                        }
                    });
                    worker.execute();
                }
            }
        });
    }
}
