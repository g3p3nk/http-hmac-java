package com.acquia.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;

/**
 * The HMACMessageCreator is a utility class to create messages that will be encrypted into HMACs.
 * 
 * @author chris.nagy
 *
 */
public class HMACMessageCreator {

    private static final String ENCODING_UTF_8 = "UTF-8";

    private static final String PARAMETER_AUTHORIZATION = "Authorization";
    private static final String PARAMETER_X_AUTHORIZATION_TIMESTAMP = "X-Authorization-Timestamp";
    private static final String PARAMETER_CONTENT_TYPE = "Content-Type";

    /**
     * Create the message based on the given HTTP request received and list of custom headers.
     * 
     * @param request HTTP request
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    public String createMessage(HttpServletRequest request) throws IOException {
        String httpVerb = request.getMethod().toUpperCase();

        int port = request.getServerPort();
        String host = request.getServerName() + (port > 0 ? ":" + port : "");
        String path = request.getRequestURI();
        String queryParameters = request.getQueryString();
        if (queryParameters == null) {
            queryParameters = "";
        }

        String authorization = request.getHeader(PARAMETER_AUTHORIZATION);
        HMACAuthenticationHeader authenticationHeader = HMACAuthenticationHeader.createFromHeaderValue(authorization);

        Map<String,String> authorizationCustomHeaderParameterMap = getHeaderValues(authenticationHeader.getHeaders(), request);

        String xAuthorizationTimestamp = request.getHeader(PARAMETER_X_AUTHORIZATION_TIMESTAMP);
        String contentType = request.getContentType();
        InputStream requestBody = request.getInputStream();

        return this.createMessage(httpVerb, host, path, queryParameters,
            authenticationHeader, authorizationCustomHeaderParameterMap,
            xAuthorizationTimestamp, contentType, requestBody);
    }

    /**
     * Create the message based on the given HTTP request to be sent and the list of custom header names.
     * 
     * @param request HTTP request
     * @param authenticationHeader
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    protected String createMessage(HttpRequest request, HMACAuthenticationHeader authenticationHeader) throws IOException {
        String httpVerb = request.getRequestLine().getMethod().toUpperCase();

        String host = "";
        String path = "";
        String queryParameters = "";
        try {
            URI uri = new URI(request.getRequestLine().getUri());
            int port = uri.getPort();
            host = uri.getHost() + (port > 0 ? ":" + port : "");
            path = uri.getPath();
            queryParameters = uri.getQuery();
            if (queryParameters == null) {
                queryParameters = "";
            }
        } catch(URISyntaxException e) {
            throw new IOException("Invalid URI", e);
        }

        Map<String,String> authorizationCustomHeaderParameterMap = getHeaderValues(authenticationHeader.getHeaders(), request);

        String xAuthorizationTimestamp = request.getFirstHeader(PARAMETER_X_AUTHORIZATION_TIMESTAMP).getValue();

        //optional content type
        Header contentTypeHeader = request.getFirstHeader(PARAMETER_CONTENT_TYPE);
        String contentType = "";
        if (contentTypeHeader != null) {
            contentType = contentTypeHeader.getValue();
        }

        //optional request body
        InputStream requestBody = null;
        if (request instanceof HttpEntityEnclosingRequest) {
            HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
            requestBody = entity.getContent();
        }

        return this.createMessage(httpVerb, host, path, queryParameters,
            authenticationHeader, authorizationCustomHeaderParameterMap,
            xAuthorizationTimestamp, contentType, requestBody);
    }

    /**
     * Create the message based on the given components of the request.
     * 
     * @param httpVerb; HTTP request method (GET, POST, etc)
     * @param host; HTTP "Host" request header field (including any port number)
     * @param path; HTTP request path with leading slash '/'
     * @param queryParameters; exact string sent by the client, including urlencoding, without leading question mark '?'
     * @param authorizationHeaderParameterMap; Map (key, value) of Authorization header for: "realm", "id", "nonce", "version"
     * @param authorizationCustomHeaderParameterMap; Map (key, value) of Authorization header for: "headers" - other custom signed headers
     * @param xAuthorizationTimestamp; value of X-Authorization-Timestamp header
     * @param contentType; value of Content-Type header
     * @param requestBody; request body
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    private String createMessage(String httpVerb, String host, String path, String queryParameters,
            HMACAuthenticationHeader authenticationHeader,
            Map<String, String> authorizationCustomHeaderParameterMap,
            String xAuthorizationTimestamp, String contentType, InputStream requestBody)
            throws IOException {

        StringBuilder result = new StringBuilder();

        //adding request URI information
        result.append(httpVerb.toUpperCase()).append("\n");
        result.append(host.toLowerCase()).append("\n");
        result.append(path).append("\n");
        //        result.append(URLEncoder.encode(queryParameters, ENCODING_UTF_8).replace("+", "%20")).append("\n");
        result.append(queryParameters).append("\n");

        //adding Authorization header parameters
        //    private final List<String> baseHeaderNames = Arrays.asList("id", "nonce", "realm", "version");
        result.append("id=").append( encode( authenticationHeader.getId() ) );
        result.append("&nonce=").append( encode( authenticationHeader.getNonce() ) );
        result.append("&realm=").append( encode( authenticationHeader.getRealm() ) );
        result.append("&version=").append( encode( authenticationHeader.getVersion() ) );

        result.append("\n");

        //adding Authorization custom header parameters
        List<String> sortedCustomKeyList = new ArrayList<String>(
            authorizationCustomHeaderParameterMap.keySet());
        Collections.sort(sortedCustomKeyList);
        for (String headerKey : sortedCustomKeyList) {
            result.append(headerKey.toLowerCase()).append(":").append(
                authorizationCustomHeaderParameterMap.get(headerKey)).append("\n");
        }

        //adding X-Authorization-Timestamp
        result.append(xAuthorizationTimestamp);

        //adding more if needed
        byte[] requestBodyBytes = this.convertInputStreamIntoBtyeArray(requestBody);
        if (this.isPassingRequestBody(httpVerb, requestBodyBytes)) {
            result.append("\n").append(contentType.toLowerCase());

            //calculate body hash
            byte[] encBody = DigestUtils.sha256(requestBodyBytes);
            String bodyHash = Base64.encodeBase64String(encBody); //v2 specification requires base64 encoded SHA-256
            result.append("\n").append(bodyHash);
        }
        //        System.out.println("Message to be encrypted:\n" + result);
        return result.toString();
    }

    private String encode( String value ) throws UnsupportedEncodingException {
        return URLEncoder.encode(value, ENCODING_UTF_8).replace(
                    "+", "%20");
    }
    /**
     * Convert InputStream into byte[]
     * 
     * @param inputStream
     * @return
     * @throws IOException 
     */
    private byte[] convertInputStreamIntoBtyeArray(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            return null;
        }

        byte[] byteChunk = new byte[1000];
        int length = -1;

        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        while ((length = inputStream.read(byteChunk)) != -1) {
            byteOutputStream.write(byteChunk, 0, length);
        }
        byteOutputStream.flush();
        byteOutputStream.close();
        return byteOutputStream.toByteArray();
    }

    /**
     * Method to help check if requestBody needs to be passed or can be omitted
     * 
     * @param httpVerb
     * @param requestBodyBytes
     * @return
     */
    private boolean isPassingRequestBody(String httpVerb, byte[] requestBodyBytes) {
        if (httpVerb.toUpperCase().equals("GET") || httpVerb.toUpperCase().equals("HEAD")) {
            return false;
        }

        return requestBodyBytes != null && requestBodyBytes.length > 0;
    }

    private Map<String, String> getHeaderValues(String[] headers, HttpRequest request) {
        Map<String,String> returnMap = new HashMap<String,String>();
        if ( headers == null ) {
            return returnMap;
        }
        for ( String headerKey : headers ) {
            Header header = request.getFirstHeader(headerKey);
            if ( header != null ) {
                returnMap.put(headerKey,header.getValue());
            }
        }
        
        return returnMap;
    }
    
    private Map<String, String> getHeaderValues(String[] headers, HttpServletRequest request) {
        Map<String,String> returnMap = new HashMap<String,String>();
        if ( headers == null ) {
            return returnMap;
        }
        for ( String headerKey : headers ) {
            String headerValue = request.getHeader(headerKey);
            if ( headerValue != null ) {
                returnMap.put(headerKey,headerValue);
            }
        }
        return returnMap;
    }
}
