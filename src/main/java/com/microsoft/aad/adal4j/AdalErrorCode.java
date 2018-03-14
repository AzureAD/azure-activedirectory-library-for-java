package com.microsoft.aad.adal4j;

public enum AdalErrorCode {

    UNKNOWN ("unknown"),
    AUTHORIZATION_PENDING ("authorization_pending"),
    INTERACTION_REQUIRED ("interaction_required");

    private String errorCode;

    AdalErrorCode(String errorCode){
        this.errorCode = errorCode;
    }

    @Override
    public String toString(){
        return errorCode;
    }
}
