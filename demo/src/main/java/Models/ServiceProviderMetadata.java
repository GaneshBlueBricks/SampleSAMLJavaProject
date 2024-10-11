package Models;

public class ServiceProviderMetadata {

    private String entityID;
    private String assertionConsumerServiceUrl;
    private String nameIDFormat;
    private boolean authnRequestsSigned;

    public ServiceProviderMetadata(String entityID, String acsUrl, String nameIDFormat, boolean authnRequestsSigned) {
        this.entityID = entityID;
        this.assertionConsumerServiceUrl = acsUrl;
        this.nameIDFormat = nameIDFormat;
        this.authnRequestsSigned = authnRequestsSigned;
    }

    public String getEntityID() {
        return entityID;
    }

    public void setEntityID(String entityID) {
        this.entityID = entityID;
    }

    public String getAssertionConsumerServiceUrl() {
        return assertionConsumerServiceUrl;
    }

    public void setAssertionConsumerServiceUrl(String assertionConsumerServiceUrl) {
        this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
    }

    public String getNameIDFormat() {
        return nameIDFormat;
    }

    public void setNameIDFormat(String nameIDFormat) {
        this.nameIDFormat = nameIDFormat;
    }

    public boolean isAuthnRequestsSigned() {
        return authnRequestsSigned;
    }

    public void setAuthnRequestsSigned(boolean authnRequestsSigned) {
        this.authnRequestsSigned = authnRequestsSigned;
    }
}

