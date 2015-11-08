package burp;

import burp.examples.TokenHandler;

public class BurpExtender implements IBurpExtender {

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        callbacks.setExtensionName("Burp in IDEA!");

        /**
         * Register HTTP LISTENER for handling CSRF token responses
         */
        callbacks.registerHttpListener(new TokenHandler(callbacks));
    }
}
