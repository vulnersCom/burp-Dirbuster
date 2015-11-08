package burp.zn.band;

import burp.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.URL;
import java.util.*;

public class SSRFScannerCheck implements IScannerCheck {

    static final Logger log = LogManager.getLogger(SSRFScannerCheck.class.getName());

    private final static String DNS_LOOKUP_SERVER = "http://{{HASH}}.evil.com";
    private final static String DNS_LOOKUP_SERVER_LOGS = "http://evil.com:80/logs";
    private final static long TIME_SECONDS_10 = 1000 * 10;
    private final static long TIME_SECONDS_30 = 1000 * 30;

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Map<String, IHttpRequestResponse> requestedInsertionPoints = new HashMap<>();

    public SSRFScannerCheck(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        registerChecker();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        String hash = DigestUtils.shaHex(helpers.base64Encode(baseRequestResponse.getRequest()));
        log.info("SSRF_HASH: " + hash);

        /**
         * Build new injection payload with provided DNS lookup server and provided Hash
         */
        byte[] request = insertionPoint.buildRequest(helpers.stringToBytes(DNS_LOOKUP_SERVER.replace("{{HASH}}", hash)));

        IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request);
        requestedInsertionPoints.put(hash, requestResponse);

        /**
         * Result of request we'll try to find in DNS lookup server later
         */
        return null;
    }

    private void registerChecker() {
        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                try {
                    check();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        };

        new Timer().schedule(task, TIME_SECONDS_10, TIME_SECONDS_30);
    }

    private void check() throws IOException {
        log.info("Trying check SSRF hashes");
        if (requestedInsertionPoints.isEmpty()) {
            return;
        }

        /**
         * Make request for DNS logs
         */
        URL url = new URL(DNS_LOOKUP_SERVER_LOGS);
        byte[] response = callbacks.makeHttpRequest(url.getHost(), 80, false, helpers.buildHttpRequest(url));
        String dnsResponseString = helpers.bytesToString(response);

        /**
         * Remove all insertion points
         * and add Issue to scanner for insertion points which contains in DNS Logs
         */
        requestedInsertionPoints.entrySet().removeIf(entry -> {
            boolean contains = dnsResponseString.contains(entry.getKey());
            if (contains) {
                log.warn("SSRF Found: " + entry.getKey());
                callbacks.addScanIssue(new SSRFScanIssue(callbacks, entry.getKey(), entry.getValue()));
                return true;
            }
            return false;
        });
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
