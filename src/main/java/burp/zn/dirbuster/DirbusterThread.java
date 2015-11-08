package burp.zn.dirbuster;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.zn.gui.DirbusterPanel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class DirbusterThread implements Runnable {

    static final Logger log = LogManager.getLogger(DirbusterHandler.class.getName());

    private URL url;
    private DirbusterPanel panel;
    private IBurpExtenderCallbacks callbacks;

    DirbusterThread(URL url, IBurpExtenderCallbacks callbacks, DirbusterPanel panel) {
        this.url = url;
        this.panel = panel;
        this.callbacks = callbacks;
    }

    @Override
    public void run() {
        try {
            /**
             * Make pre check, host existing
             */
            int statusCode = makeHttpRequest();
            if (
                    statusCode == 302 ||
                    statusCode == 404 ||
                    statusCode == 501 ||
                    statusCode == 502) {
                return;
            }
            log.info("Status code: ---" + statusCode + "--- Found path " + url);

            /**
             * Add data to GUI table model
             */
            ((DefaultTableModel) panel.getTblFoundDirs().getModel()).addRow(new Object[]{true, url, statusCode});

            /**
             * Send to spider this host
             */
            if (!callbacks.isInScope(url)) {
                callbacks.includeInScope(url);
            }
            callbacks.sendToSpider(url);
            log.info("Sent to Spider: " + url);
        } catch (Exception e) {
            log.error("Error make HTTP Request: " + url + e.getMessage());
        }
    }

    /**
     * Make Http request to url
     * @return HTTP status code
     * @throws IOException
     */
    private int makeHttpRequest() throws IOException {
        HttpURLConnection.setFollowRedirects(false);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setConnectTimeout(Integer.valueOf(panel.getTbxTimeout().getText()));
        con.setRequestMethod("HEAD");

        return con.getResponseCode();
    }
}
