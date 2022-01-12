package com.github.sellers.qrcodeverifier;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

public class QRCodeScannerSpikeTest {

    @Test
    public void smokeTest() {
        QRCodeScannerSpike spike = new QRCodeScannerSpike();
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
}
