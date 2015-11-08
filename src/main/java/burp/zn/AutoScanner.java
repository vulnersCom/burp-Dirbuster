package burp.zn;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanQueueItem;
import burp.zn.dirbuster.DirbusterHandler;
import burp.zn.gui.Tab;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.Thread.sleep;

public class AutoScanner {

    private final static String HOST = "http://victim.com";
    static final Logger log = LogManager.getLogger(AutoScanner.class.getName());

    private Tab tab;
    private IBurpExtenderCallbacks callbacks;
    private List<IScanQueueItem> scanQueueItems = new ArrayList<>();

    public AutoScanner(IBurpExtenderCallbacks callbacks, Tab tab) {
        this.callbacks = callbacks;
        this.tab = tab;
    }

    public void startScan() {
        try {
            /**
             * Get command line arguments
             * Or you can take arguments from System Env
             */
            String[] args = callbacks.getCommandLineArguments();
            URL url = new URL(args[0], args[1], Integer.valueOf(args[2]), "");
            String dictionaryFilePath = args[3];

            tab.getPanel().getTbxHost().setText(url.toString());
            log.info("Start scan host with arguments\n   " + url + "\n   " + dictionaryFilePath);

            doDirBuster(dictionaryFilePath);
            doScan(url);
            doReport(url);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Run new DirBuster thread
     *
     * @param dictionaryFilePath path to DirBuster dictionary file
     * @throws InterruptedException
     */
    private void doDirBuster(String dictionaryFilePath) throws InterruptedException {
        DirbusterHandler dirbuster = tab.getHandler();

        /**
         * Run DirBuster in new thread
         */
        new Thread(() -> {
            try {
                log.info("Start DirBuster");
                dirbuster.runDirBuster(dictionaryFilePath);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();

        /**
         * Waiting new Thread start DirBuster and it make his work
         */
        sleep(3000);
        while (dirbuster.isWorking()) {
            sleep(300);
            log.info("DirBuster working...");
        }
        log.info("DirBuster has done his work...");
    }

    /**
     * @param url URL of scanning host
     * @throws InterruptedException
     * @throws MalformedURLException
     */
    private void doScan(URL url) throws InterruptedException, MalformedURLException {
        /**
         * Start scan by found items
         */
        log.info("Start actively scan host..." + url);
        IHttpRequestResponse[] siteMap = callbacks.getSiteMap(HOST);
        Arrays.stream(siteMap).forEach(requestResponse -> {
            /**
             * Here we can use burp's IScanQueueItem
             * to detect if item scan complete or not
             */
            IScanQueueItem item = callbacks.doActiveScan(url.getHost(), url.getPort(), url.getProtocol().equals("https"), requestResponse.getRequest());
            log.info("URL has been sent to scan: " + callbacks.getHelpers().analyzeRequest(requestResponse).getUrl());
            scanQueueItems.add(item);
        });

        /**
         * Check if scan items have been scanned
         */
        log.info("Start check items have been scanned");
        while (!scanQueueItems.isEmpty()) {
            sleep(1000);
            log.warn("Scanning =======================>");
            scanQueueItems.removeIf(item -> {
                log.info(item.getStatus());
                return item.getPercentageComplete() == 100;
            });
        }
        log.info("DONE. All items has been scanned");
    }

    /**
     * Just prints a report to File
     *
     * @param url URL of scanning host
     */
    private void doReport(URL url) {
        /**
         * Finally generate scan issues
         */
        File reportFile = new File(System.getProperty("user.home") + File.separator + "burp_scanner_report.html");
        callbacks.generateScanReport(
                "HTML",
                callbacks.getScanIssues(HOST),
                reportFile
        );

        log.warn("Finished autoscan host " + url + " you can find report here: file://" + reportFile.getAbsolutePath());
    }
}
