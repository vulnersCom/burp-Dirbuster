package burp;

import burp.zn.AutoScanner;
import burp.zn.TokenHandler;
import burp.zn.csrf.CSRFTokenScanner;
import burp.zn.gui.Tab;
import burp.zn.band.SSRFScannerCheck;

public class BurpExtender implements IBurpExtender {

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        callbacks.setExtensionName("ZN Burp Extension");

        /**
         * Register HTTP LISTENER for handling CSRF token responses
         */
//        callbacks.registerHttpListener(new TokenHandler(callbacks));

        /**
         * Register CSRF-Token form Scanner check
         */
//        callbacks.registerScannerCheck(new CSRFTokenScanner(callbacks));

        /**
         * Register SSRF Scanner check
         */
//        callbacks.registerScannerCheck(new SSRFScannerCheck(callbacks));

        /**
         * Register GUI Tab
         */
        Tab tab = new Tab(callbacks);
        callbacks.addSuiteTab(tab);

        /**
         * Start auto-tests
         */
//        if (callbacks.getCommandLineArguments().length > 0) {
//            new AutoScanner(callbacks, tab).startScan();
//        }
    }
}
