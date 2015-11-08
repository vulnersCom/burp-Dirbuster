package burp.zn.csrf;

import burp.*;
import org.apache.commons.lang3.StringEscapeUtils;

import java.net.URL;
import java.util.List;

public class CSRFTokenScanIssue implements IScanIssue {

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final IHttpRequestResponse requestResponse;

    public CSRFTokenScanIssue(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.requestResponse = requestResponse;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public URL getUrl() {
        return helpers.analyzeRequest(requestResponse).getUrl();
    }

    @Override
    public String getIssueName() {
        return "CSRF token Not Found";
    }

    @Override
    public int getIssueType() {
        return 1337;
    }

    @Override
    public String getSeverity() {
        return "Medium";
    }

    @Override
    public String getConfidence() {
        return "Firm";
    }

    @Override
    public String getIssueBackground() {
        return "There is possible CSRF at current url";
    }

    @Override
    public String getRemediationBackground() {
        return "You should implement CSRF token for this form submission request";
    }

    @Override
    public String getIssueDetail() {
        StringBuilder details = new StringBuilder()
                .append("CSRF attack possible in this form. Please read more completely about this in OWASP TOP-10");

        String stringResponse = callbacks.getHelpers().bytesToString(requestResponse.getResponse());
        List<int[]> markers = ((IHttpRequestResponseWithMarkers) requestResponse).getResponseMarkers();
        markers.forEach(marker -> {
            details.append("<br/>");
            details.append(
                    StringEscapeUtils.escapeHtml4(stringResponse.substring(marker[0], marker[1]))
            );
        });
        details.append("<br/><img src=\"http://www.terrariaonline.com/attachments/small-trollface-jpg.9747/\">");

        return details.toString();
    }

    @Override
    public String getRemediationDetail() {
        return "Seriously, You should implement CSRF token for this form submission request!";
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[]{requestResponse};
    }

    @Override
    public IHttpService getHttpService() {
        return requestResponse.getHttpService();
    }
}
