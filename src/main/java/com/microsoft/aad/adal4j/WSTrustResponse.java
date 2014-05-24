package com.microsoft.aad.adal4j;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

public class WSTrustResponse {

	public static WSTrustResponse processResponse(
			HttpURLConnection httpUrlConnection) {
		WSTrustResponse wsTrustResponse = new WSTrustResponse();
		HTTPResponse response = null;
		try {
			response = createResponse(httpUrlConnection);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String content = response.getContent();
		System.out.println(content);
		return wsTrustResponse;
	}
	
    static HTTPResponse createResponse(final HttpURLConnection conn)
            throws IOException {
        final HTTPResponse response = new HTTPResponse(conn.getResponseCode());
        final String location = conn.getHeaderField("Location");
        if (!StringHelper.isBlank(location)) {
            response.setLocation(new URL(location));
        }

        try {
            response.setContentType(conn.getContentType());
        } catch (final ParseException e) {
            throw new IOException("Couldn't parse Content-Type header: "
                    + e.getMessage(), e);
        }

        response.setCacheControl(conn.getHeaderField("Cache-Control"));
        response.setPragma(conn.getHeaderField("Pragma"));
        response.setWWWAuthenticate(conn.getHeaderField("WWW-Authenticate"));
        return response;
    }

}
