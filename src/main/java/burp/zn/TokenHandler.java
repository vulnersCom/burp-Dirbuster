package burp.zn;

import burp.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;

import java.util.Arrays;

public class TokenHandler implements IHttpListener {

    private static final Logger log = LogManager.getLogger(TokenHandler.class.getName());
    private static final String TOKEN = "TOKEN";

    private final byte[] tokenBytesPattern;
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;

    public TokenHandler(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.tokenBytesPattern = helpers.stringToBytes(TOKEN);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        if (messageIsRequest ||
                (toolFlag != IBurpExtenderCallbacks.TOOL_REPEATER) &&
                (toolFlag != IBurpExtenderCallbacks.TOOL_SCANNER)) {
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
        if (!responseString.contains(TOKEN)) {
            return;
        }

        /**
         * If you want to improve speed, better to use @IExtentionHelpers.indexOf
         * BTW it's a wrapped native java.lang.String.indexOf
         */
//        if (helpers.indexOf(responseBytes, tokenBytesPattern, true, 0, responseBytes.length) == -1) {
//            return;
//        }

        /**
         * IResponseInfo
         */
        IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);

        /**
         * String Response body
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
        newRequest = helpers.toggleRequestMethod(newRequest); // Changes a request method GET to POST

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
            return node.get(TOKEN)
                    .getTextValue();
        } catch (Exception e) {
            log.error("Error while reading json: " + e.getMessage());
            return "";
        }

    }
}
