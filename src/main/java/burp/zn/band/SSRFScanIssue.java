package burp.zn.band;

import burp.*;

import java.net.URL;

public class SSRFScanIssue implements IScanIssue {

    private final String requestHash;
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final IHttpRequestResponse requestResponse;

    public SSRFScanIssue(IBurpExtenderCallbacks callbacks, String requestHash, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.requestHash = requestHash;
        this.requestResponse = requestResponse;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public URL getUrl() {
        return helpers.analyzeRequest(requestResponse).getUrl();
    }

    @Override
    public String getIssueName() {
        return "Server Side Request Forgery";
    }

    @Override
    public int getIssueType() {
        return 31337;
    }

    @Override
    public String getSeverity() {
        return "High";
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return "SSRF here, guys!";
    }

    @Override
    public String getRemediationBackground() {
        return "You've pwned this host!";
    }

    @Override
    public String getIssueDetail() {
        return "SSRF found with this request hash <br/>" + requestHash +
                "<br/><img src=\"http://www.terrariaonline.com/attachments/small-trollface-jpg.9747/\">";
    }

    @Override
    public String getRemediationDetail() {
        return "Pwn'em all!";
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
