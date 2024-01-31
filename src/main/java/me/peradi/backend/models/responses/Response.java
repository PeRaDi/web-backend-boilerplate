package me.peradi.backend.models.responses;

public class Response {
    private int status;
    private String message;
    private Object values;

    public Response(int status, String message, Object values) {
        this.status = status;
        this.message = message;
        this.values = values;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Object getValues() {
        return values;
    }

    public void setValues(Object values) {
        this.values = values;
    }
}
