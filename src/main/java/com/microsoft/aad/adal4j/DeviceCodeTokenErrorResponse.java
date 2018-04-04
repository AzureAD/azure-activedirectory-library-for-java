package com.microsoft.aad.adal4j;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.jcip.annotations.Immutable;

/**
 * Error object used to encapsulated the device code errors.
 */
@Immutable
public class DeviceCodeTokenErrorResponse extends TokenErrorResponse {
    /**
     * Creates a new device code token error response.
     *
     * @param error The error.
     */
    public DeviceCodeTokenErrorResponse(final ErrorObject error) {
        super(error);
    }

    /**
     * Checks if is a device code error.
     *
     * @return true if is one of the well known device code error code, otherwise false.
     */
    public boolean isDeviceCodeError() {
        ErrorObject errorObject = getErrorObject();
        if (errorObject == null) {
            return false;
        }
        String code = errorObject.getCode();
        if (code == null) {
            return false;
        }
        switch (code) {
            case "authorization_pending":
            case "slow_down":
            case "access_denied":
            case "code_expired":
                return true;
            default:
                return false;
        }
    }

    /**
     * Parses an device code Token Error response from the specified HTTP
     * response.
     *
     * @param httpResponse The HTTP response to parse.
     *
     * @return A DeviceCodeTokenErrorResponse which may contain a device code error.
     */
    public static DeviceCodeTokenErrorResponse parse(final HTTPResponse httpResponse) {
        return new DeviceCodeTokenErrorResponse(ErrorObject.parse(httpResponse));
    }

}
