package com.github.sellers.qrcodeverifier;

import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.reflect.MethodUtils;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;

/**
 * This class is more to download the keysets and write them to a file. If the file is good, we can
 * copy this into the project and not have any outbound network connections that might fail at
 * validation time.
 * 
 * This probably shouldn't be a test, but that's something to consider changing in the future.
 * 
 * @author sellersj
 */
public class CreateKeySetStoreTest {

    /** The standard path for the key store. Required to be passed if using a proxy. */
    private static final String WELL_KNOWN_JWKS_PATH = "/.well-known/jwks.json";

    private static final List<String> BASE_URLS_OF_KEY_STORES = Arrays.asList( //
        "https://prd.pkey.dhdp.ontariohealth.ca", //
        "https://covid19.quebec.ca/PreuveVaccinaleApi/issuer" //
    );

    @Test
    public void downloadTheKeyStores() throws Exception {
        Map<String, JWKSet> map = new HashMap<>();
        for (String baseUrl : BASE_URLS_OF_KEY_STORES) {
            RemoteJWKSet<?> jwk = new RemoteJWKSet<>(new URL(baseUrl + WELL_KNOWN_JWKS_PATH));

            // TODO fix this since it doesn't seem to properly populate the keys. Might have to hard
            // code the base keys or just manually get the data from another source

            // trigger retrieval of the key over the internet so we can store it to a local file
            // hack to get around calling a private method
            JWKSet keySet = (JWKSet) MethodUtils.invokeMethod(jwk, true, "updateJWKSetFromURL");
            map.put(baseUrl, keySet);
        }

        System.out.println(JSONObjectUtils.toJSONString(map));
    }
}
