package com.github.sellers.qrcodeverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.jamsesso.jsonlogic.JsonLogic;

public class QRCodeScannerSpikeTest {

    private QRCodeScannerSpike spike = new QRCodeScannerSpike();

    @Test
    public void smokeTest() {
        // Path where the QR code is saved
        List<File> files = new ArrayList<>();

        for (String provCode : Arrays.asList("on", "qc")) {
            files.add(new File(
                System.getProperty("user.home") + "/Downloads/vax-certs/example-covid-generated-" + provCode + ".pdf"));
        }

        // try to validate these
        for (File file : files) {
            spike.readFromPdfs(file);
        }
    }

    @Test
    public void loadOntarioTrustKeys() {
        Map<String, JWKSource<SecurityContext>> keys = spike.loadOntarioTrustKeys();

        assertEquals(31, keys.size(),
            "should be the correct number of key groups that match provinces and territories");

        // smoke test of Ontario key
        assertTrue(keys.containsKey("https://prd.pkey.dhdp.ontariohealth.ca"), "should have had ontario key");

        // quick check for null on all the keys
        for (Entry<String, JWKSource<SecurityContext>> entry : keys.entrySet()) {
            assertNotNull(entry.getKey(), "key shouldbn't be null");
            assertNotNull(entry.getValue(), "value shouldbn't be null");
        }
    }

    // TODO see if we need this. Test for checking io.github.jamsesso:json-logic-java
    @Test
    @Disabled("a check of some outputs that are temp")
    public void validateRules() throws Exception {
        String dir = "/Users/sellersj/Documents/workspace/Temp/src/main/resources/";
        String data = FileUtils.readFileToString(new File(dir + "temp3.json"), StandardCharsets.ISO_8859_1);
        String rules = FileUtils.readFileToString(new File(dir + "temp2.json"), StandardCharsets.ISO_8859_1);

        JsonLogic jsonLogic = new JsonLogic();

        // Evaluate the result.
        double result;
        result = (double) jsonLogic.apply(rules, data);
        assert result == 20.0;
    }
}
