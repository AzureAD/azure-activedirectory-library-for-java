package com.microsoft.aad.adal4j;

import com.nimbusds.oauth2.sdk.util.URLUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocketFactory;
import java.net.Proxy;
import java.util.HashMap;
import java.util.Map;

public class DeviceCodeRequest {

    private final static Logger log = LoggerFactory.getLogger(DeviceCodeRequest.class);

    static DeviceCode execute(String url, String clientId, String resource, Map<String, String> clientDataHeaders,
                              final Proxy proxy, final SSLSocketFactory sslSocketFactory) throws Exception {
        Map<String, String> headers = new HashMap<>(clientDataHeaders);
        headers.put("Accept", "application/json");

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("client_id", clientId);
        queryParameters.put("resource", resource);

        url = url + "?" + URLUtils.serializeParameters(queryParameters);

        final String json = HttpHelper.executeHttpGet(log, url, headers, proxy, sslSocketFactory);

        DeviceCode result;
        result = JsonHelper.convertJsonToObject(json, DeviceCode.class);

        result.setCorrelationId(headers.get(ClientDataHttpHeaders.CORRELATION_ID_HEADER_NAME));

        result.setClientId(clientId);
        result.setResource(resource);

        return result;
    }
}
