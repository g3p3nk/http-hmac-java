package com.acquia.http;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author chris.nagy
 */
public class HMACAuthenticationHeader {
    private String realm;
    private String id;
    private String nonce;
    private String version;
    private String[] headers = new String[0];
    private String signature;
    
        /**
     * @return the realm
     */
    public String getRealm() {
        return realm;
    }

    /**
     * @param realm the realm to set
     */
    public void setRealm(String realm) {
        this.realm = realm;
    }

    /**
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * @param id the id to set
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * @return the nonce
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * @param nonce the nonce to set
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    /**
     * @return the version
     */
    public String getVersion() {
        return version;
    }

    /**
     * @param version the version to set
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * @return the headers
     */
    public String[] getHeaders() {
        return headers;
    }

    /**
     * @param headers the headers to set
     */
    public void setHeaders(String[] headers) {
        this.headers = headers;
    }

    /**
     * @return the signature
     */
    public String getSignature() {
        return signature;
    }

    /**
     * @param signature the signature to set
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }
          
    
    public static HMACAuthenticationHeader createFromHeaderValue(String headerValue) {
        int indexSpace = headerValue.indexOf(" ");
        String authContent = headerValue.substring(indexSpace + 1);
        String[] authParams = authContent.split(",");

        Map<String, String> theMap = new HashMap<String, String>();
        for (String param : authParams) {
            int indexDelimiter = param.indexOf("="); //first index of delimiter
            String key = param.substring(0, indexDelimiter);
            String val = param.substring(indexDelimiter + 1);
            theMap.put(key.toLowerCase(), val.substring(1, val.length() - 1)); //remove "" from val
        }
        
        HMACAuthenticationHeader returnHeader = new HMACAuthenticationHeader();
        returnHeader.setRealm(theMap.get("realm"));
        returnHeader.setId(theMap.get("id"));
        returnHeader.setNonce(theMap.get("nonce"));
        if ( theMap.containsKey("headers") ) {
            returnHeader.setHeaders(theMap.get("header").split(";"));
        }
        returnHeader.setVersion(theMap.get("version"));
        returnHeader.setSignature(theMap.get("signature"));
        
        return returnHeader;
    }
    
    public String toString() {
      StringBuilder authBuilder = new StringBuilder();
        authBuilder.append("acquia-http-hmac realm=\"").append(getRealm()).append("\",");
        authBuilder.append("id=\"").append(getId()).append("\",");
        authBuilder.append("nonce=\"").append(getNonce()).append("\",");
        authBuilder.append("version=\"").append(getVersion()).append("\"");

        if (getHeaders() != null && getHeaders().length > 0) {
            authBuilder.append(",headers=\"");
            for ( int i = 0; i < getHeaders().length; i++ ) {
                if ( i > 0 ) {
                    authBuilder.append(";");
                }
                authBuilder.append(getHeaders()[i]);
            }
            authBuilder.append("\"");
        }

        if (getSignature() != null && getSignature().length() > 0) {
            authBuilder.append(",signature=\"").append(getSignature()).append("\"");
        }

        return authBuilder.toString();  
    }

  
}
