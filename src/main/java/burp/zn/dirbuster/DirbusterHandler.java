package burp.zn.dirbuster;

import burp.IBurpExtenderCallbacks;
import burp.zn.gui.DirbusterPanel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class DirbusterHandler {

    private static final String START = "Start";
    private static final String STOP = "Stop";

    private int counter;
    private DirbusterPanel panel;
    private JFileChooser fileChooser;
    private ThreadPoolExecutor executor;
    private IBurpExtenderCallbacks callbacks;
    private boolean isWorking = false;

    public DirbusterHandler(DirbusterPanel panel, IBurpExtenderCallbacks callbacks) {
        this.panel = panel;
        this.callbacks = callbacks;
        this.fileChooser = panel.getFileChooser();

        /**
         * Set event handler for Dirbuster start button
         * Each gui handler must run in new thread
         */
        panel.getBtnStart().addActionListener(e1 -> new Thread(() -> {
            if (isWorking) {
                DirbusterHandler.this.onCancelClick();
            } else {
                DirbusterHandler.this.onStartClick();
            }
        }).start());

        /**
         * Browse button handler
         */
        panel.getBtnBrowse().addActionListener(e -> new Thread(() -> {
            int returnVal = fileChooser.showOpenDialog(panel.getRootPanel());

            if (returnVal == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                panel.getTbxPathToFile().setText(file.getPath());
            }
        }).start());
    }

    /**
     * Start Button Handler
     */
    private void onStartClick() {

        /**
         * Check dictionary file exist and change btn text
         */
        File file = this.fileChooser.getSelectedFile() != null
                ? this.fileChooser.getSelectedFile()
                : new File(panel.getTbxPathToFile().getText());

        if (!file.exists()) {
            /**
             * Any kinds of logging
             */
            callbacks.issueAlert("DirBuster dictionary file is Null");
            callbacks.printError("DirBuster dictionary file is Null");
            callbacks.printOutput("DirBuster dictionary file is Null");
            return;
        }

        panel.getBtnStart().setText(STOP);

        try {
            /**
             * Finally start buster
             */
            this.runDirBuster(file.getAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Dirbuster Executor
     *
     * @throws IOException
     */
    public void runDirBuster(String filePath) throws IOException {
        /**
         * New thread pool with max count from panel
         */
        this.executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Integer.valueOf(panel.getTbxMaxThreads().getText()));
        this.counter = 0;
        this.isWorking = true;

        /**
         * Using Lambdas and streams, is easier to make better performance in IO (because of parallel),
         * easy for use and more pretty code
         */
        Files.lines(Paths.get(filePath))
                .skip(13)
                .limit(3500)
                .parallel()
                .forEach(this::checkHost);

        this.onCancelClick();
    }

    /**
     * Handle new line
     */
    private void checkHost(String filePath) {
        Future<?> future = executor.submit(new DirbusterThread(getURL(filePath), callbacks, panel));

        try {
            panel.getLblCount().setText("Count of bustered dirs: " + String.valueOf(counter++));
            /**
             * New feature with thread timeout from the panel
             */
            future.get(Integer.valueOf(panel.getTbxTimeout().getText()), TimeUnit.MILLISECONDS);
        } catch (Exception ex) {
            future.cancel(true);
        }
    }

    public URL getURL(String line) {
        String host = panel.getTbxHost().getText() + "/" + line + panel.getTbxFileExtention().getText();

        try {
            return new URL(host);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Stop Button Handler
     */
    private void onCancelClick() {
        isWorking = false;
        panel.getBtnStart().setText(START);
        executor.shutdownNow();
    }

    public boolean isWorking() {
        return isWorking;
    }
}
