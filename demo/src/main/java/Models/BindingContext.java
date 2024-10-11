package Models;

public class BindingContext {

    private String content;  // Can be URL for Redirect binding or HTML form for Post binding
    private String bindingType;  // "redirect" or "post"

    public BindingContext(String content, String bindingType) {
        this.content = content;
        this.bindingType = bindingType;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getBindingType() {
        return bindingType;
    }

    public void setBindingType(String bindingType) {
        this.bindingType = bindingType;
    }
}

