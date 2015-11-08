package burp.zn.csrf;

import burp.*;
import burp.zn.dirbuster.DirbusterHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CSRFTokenScanner implements IScannerCheck {

    private static final Logger log = LogManager.getLogger(DirbusterHandler.class.getName());

    private static final Pattern CONTENT_HTML = Pattern.compile("Content-Type: text/html", Pattern.CASE_INSENSITIVE);
    private static final Pattern FORM_PATTERN = Pattern.compile("<form.+class=\"form-submit\".+>", Pattern.CASE_INSENSITIVE);
    private static final Pattern CSRF_TOKEN_PATTERN = Pattern.compile("csrfToken=", Pattern.CASE_INSENSITIVE);

    private final byte[] htmlFormPattern;
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;

    public CSRFTokenScanner(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.htmlFormPattern = helpers.stringToBytes("<form");
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse) {
        return doActiveScan(requestResponse, null);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse requestResponse, IScannerInsertionPoint insertionPoint) {

        byte[] responseBytes = requestResponse.getResponse();
        String responseString = helpers.bytesToString(responseBytes);
        IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
        List<String> responseHeaders = responseInfo.getHeaders();

        log.info("Trying to find Token form in: " + helpers.analyzeRequest(requestResponse).getUrl());

        /**
         * Check if content type is text/html
         */
        boolean isHTML = responseHeaders.stream()
                .filter(s -> CONTENT_HTML.matcher(s).find())
                .findFirst()
                .isPresent();

        if (!isHTML) {
            return null;
        }

        /**
         * Check if html body contains form tags
         */
        int formTagOffset = helpers.indexOf(responseBytes, htmlFormPattern, false, 0, responseBytes.length);
        if (formTagOffset == -1) {
            return null;
        }

        /**
         * Start finding matched regions
         */
        List<int[]> matchedRegions = new ArrayList<>();
        Matcher matcher = FORM_PATTERN.matcher(responseString);
        while (matcher.find()) {
            int from = matcher.start();
            int to =  matcher.end();

            if (!CSRF_TOKEN_PATTERN.matcher(responseString.substring(from, to)).find()) {
                matchedRegions.add(new int[]{from, to});
            }
        }

        if (matchedRegions.isEmpty()) {
            return null;
        }

        /**
         * Apply found markers for response
         */
        log.info("Found form without token: " + helpers.analyzeRequest(requestResponse).getUrl());
        return new ArrayList<IScanIssue>() {{
            add(new CSRFTokenScanIssue(callbacks, callbacks.applyMarkers(requestResponse, null, matchedRegions)));
        }};
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (Objects.equals(existingIssue.getIssueDetail(), newIssue.getIssueDetail()) &&
                existingIssue.getIssueType() == newIssue.getIssueType() &&
                existingIssue.getUrl().equals(newIssue.getUrl())) return -1;
        else return 1;
    }
}
