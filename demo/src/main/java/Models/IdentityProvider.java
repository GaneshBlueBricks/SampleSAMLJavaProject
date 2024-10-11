package Models;

import java.security.PrivateKey;

public class IdentityProvider {

    private String entityID;
    private String ssoRedirectUrl;
    private String ssoPostUrl;
    private PrivateKey privateKey;

    public IdentityProvider(String entityID, String ssoRedirectUrl, String ssoPostUrl, PrivateKey privateKey) {
        this.entityID = entityID;
        this.ssoRedirectUrl = ssoRedirectUrl;
        this.ssoPostUrl = ssoPostUrl;
        this.privateKey = privateKey;
    }

    public String getEntityID() {
        return entityID;
    }

    public void setEntityID(String entityID) {
        this.entityID = entityID;
    }

    public String getSingleSignOnServiceUrl(String bindingType) {
        if ("HTTP-Redirect".equalsIgnoreCase(bindingType)) {
            return ssoRedirectUrl;
        } else if ("HTTP-POST".equalsIgnoreCase(bindingType)) {
            return ssoPostUrl;
        }
        throw new IllegalArgumentException("Unsupported binding type: " + bindingType);
    }

    public void setSsoRedirectUrl(String ssoRedirectUrl) {
        this.ssoRedirectUrl = ssoRedirectUrl;
    }

    public void setSsoPostUrl(String ssoPostUrl) {
        this.ssoPostUrl = ssoPostUrl;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
