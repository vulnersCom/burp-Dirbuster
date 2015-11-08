package burp.zn.gui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.zn.dirbuster.DirbusterHandler;

import javax.swing.*;
import java.awt.*;

public class Tab implements ITab {

    private JFrame frame;
    private DirbusterPanel panel;
    private DirbusterHandler handler;

    public Tab(IBurpExtenderCallbacks callbacks) {
        /**
         * Compile Gui from GUI Designer config
         */
        this.panel = new DirbusterPanel();
        this.frame = new JFrame();
        frame.setContentPane(panel.getRootPanel());
        frame.pack();

        /**
         * Set event handlers for panel
         */
        this.handler = new DirbusterHandler(panel, callbacks);
    }

    public DirbusterPanel getPanel() {
        return panel;
    }

    public DirbusterHandler getHandler() {
        return handler;
    }

    @Override
    public String getTabCaption() {
        return "Dirbuster";
    }

    @Override
    public Component getUiComponent() {
        return frame.getContentPane();
    }

    /**
     * Debug method, to check how gui creates
     * @param args
     */
    static public void main(String args[]) {
        JFrame frame = new JFrame("");
        frame.setContentPane(new DirbusterPanel().getRootPanel());
        frame.pack();

        frame.setPreferredSize(new Dimension(1200, 1200));
        frame.setVisible(true);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
}
