package burp.examples;

import burp.*;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;

import java.util.Arrays;

public class TokenHandler implements IHttpListener {

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;

    public TokenHandler(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        if (messageIsRequest || toolFlag != IBurpExtenderCallbacks.TOOL_REPEATER) {
            return;
        }

        /**
         * Response Bytes
         */
        byte[] responseBytes = messageInfo.getResponse();

        /**
         * Check Response String contains TOKEN parameter
         */
        String responseString = helpers.bytesToString(responseBytes);
        if (!responseString.contains("TOKEN")) {
            return;
        }

        /**
         * IResponseInfo
         */
        IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);

        /**
         * Response body
         */
        String responseBody = helpers.bytesToString(Arrays.copyOfRange(
                responseBytes, responseInfo.getBodyOffset(), responseBytes.length));

        /**
         * Extract Jackson JSON node info and string CSRF token
         */
        String token = readNode(responseBody);
        if (token.equals("")) {
            return;
        }

        /**
         * Add new request parameter to the existing request
         */
        byte[] newRequest = helpers.addParameter(
                messageInfo.getRequest(),
                helpers.buildParameter("token", token, IParameter.PARAM_BODY));

        /**
         * Send request with added token parameter
         */
        IHttpRequestResponse newResponse = callbacks.makeHttpRequest(
                messageInfo.getHttpService(),
                newRequest);

        /**
         * Finally talks burp that new response is
         */
        messageInfo.setResponse(newResponse.getResponse());
    }

    /**
     * Read JSON with Jackson ObjectMapper
     * @param stringNode JSON string body
     * @return JSON node
     */
    private String readNode(String stringNode) {
        ObjectMapper mapper = new ObjectMapper();

        try {
            JsonNode node = mapper.readTree(stringNode);
            return node.get("data")
                    .get("token")
                    .getTextValue();
        } catch (Exception e) {
            System.out.println("[Token Handler] Error while reading json: " + e.getMessage());
            return "";
        }

    }
}
