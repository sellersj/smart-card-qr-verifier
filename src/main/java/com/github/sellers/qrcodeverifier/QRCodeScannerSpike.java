package com.github.sellers.qrcodeverifier;

import java.awt.image.BufferedImage;
import java.awt.image.RenderedImage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.imageio.ImageIO;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.graphics.PDXObject;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.tools.imageio.ImageIOUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 *
 * @author sellersj
 */
public class QRCodeScannerSpike {

    private static final Logger LOGGER = LoggerFactory.getLogger(QRCodeScannerSpike.class);

    private static final String QR_CODE_PREFIX = "shc:/";

    public List<RenderedImage> getImagesFromPDF(PDDocument document) throws IOException {
        List<RenderedImage> images = new ArrayList<>();
        for (PDPage page : document.getPages()) {
            images.addAll(getImagesFromResources(page.getResources()));
        }

        return images;
    }

    private List<RenderedImage> getImagesFromResources(PDResources resources) throws IOException {
        List<RenderedImage> images = new ArrayList<>();

        for (COSName xObjectName : resources.getXObjectNames()) {
            PDXObject xObject = resources.getXObject(xObjectName);

            if (xObject instanceof PDFormXObject) {
                images.addAll(getImagesFromResources(((PDFormXObject) xObject).getResources()));
            } else if (xObject instanceof PDImageXObject) {
                images.add(((PDImageXObject) xObject).getImage());
            }
        }

        return images;
    }

    private String decodeQRCode(BufferedImage qrCodeImage) {
        Result result = null;
        try {
            LuminanceSource source = new BufferedImageLuminanceSource(qrCodeImage);
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));

            Map<DecodeHintType, Object> hints = new HashMap<>();
            hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
            hints.put(DecodeHintType.POSSIBLE_FORMATS, Arrays.asList(BarcodeFormat.QR_CODE));
            hints.put(DecodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name());

            result = new MultiFormatReader().decode(bitmap, hints);
            return result.getText();
        } catch (NotFoundException e) {
            LOGGER.debug("QRCode not found", e);
        }

        // if we are here, it didn't work.
        // TODO change this to be an optional
        return null;
    }

    public void readFromPdfs(File file) {
        if (!file.exists()) {
            throw new IllegalArgumentException("The file " + file.getAbsolutePath() + " does not exist!");
        }

        // TODO put this somewhere else with object creation
        Map<String, JWKSource<SecurityContext>> trustKeys = loadOntarioTrustKeys();

        List<String> qrCodesFromPdf = getQrCodesFromPdf(file);

        for (String qrCode : qrCodesFromPdf) {
            String rawJwt = smartQrCodeToJwt(qrCode);
            validateToken(rawJwt, trustKeys);
        }
    }

    private List<String> getQrCodesFromPdf(File file) {
        List<String> result = new ArrayList<>();

        try (PDDocument pdDoc = PDDocument.load(file)) {

            List<RenderedImage> images = getImagesFromPDF(pdDoc);

            // we couldn't find any images, try making the pdf a image and getting the QR code from
            // that
            if (images.isEmpty()) {
                LOGGER.info("Could not find a QR image in file. Trying the convert to an image route for "
                    + file.getAbsolutePath());
                images.addAll(convertPdfToImages(file));
            }

            LOGGER.debug(String.format("Found %s images in file %s", images.size(), file));
            for (RenderedImage renderedImage : images) {
                // System.out.println(renderedImage);

                String qrCode = decodeQRCode(toBufferedImage(renderedImage));
                if (null != qrCode && qrCode.startsWith(QR_CODE_PREFIX)) {
                    result.add(qrCode);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not read pdf file " + file, e);
        }

        return result;
    }

    /**
     * If we can't pull the images right out of the pdf, then we are going to try to convert the whole page to a pdf and
     * try to scan the code from that.
     *
     * @param file to check
     * @return an image per page
     */
    private List<BufferedImage> convertPdfToImages(File file) {
        List<BufferedImage> result = new ArrayList<>();

        // make the pdf into a high quality bitmap
        try (PDDocument document = PDDocument.load(file)) {
            PDFRenderer pdfRenderer = new PDFRenderer(document);
            for (int page = 0; page < document.getNumberOfPages(); ++page) {
                BufferedImage bim = pdfRenderer.renderImageWithDPI(page, 300, ImageType.BINARY);

                // suffix in filename will be used as the file format
                File pngFile = File.createTempFile(file.getName() + "-" + (page + 1) + System.currentTimeMillis() + "-",
                    ".png");
                pngFile.deleteOnExit();
                ImageIOUtil.writeImage(bim, pngFile.getAbsolutePath(), 300);

                // each page will be a new image to scan
                result.add(ImageIO.read(pngFile));
            }
        } catch (IOException e) {
            throw new RuntimeException(String.format("Could not convert pdf pages to a image for file " + file), e);
        }

        return result;
    }

    /**
     *
     * TODO consider changing a parser that implements JWTParser
     *
     * @param qrCode smart health card QR code
     * @return a JWT token with a compressed payload
     * @throws Exception
     */
    private String smartQrCodeToJwt(String qrCode) {
        if (!qrCode.startsWith(QR_CODE_PREFIX)) {
            throw new IllegalArgumentException("this is not a valid qr code " + qrCode);
        }

        String code = qrCode.substring(QR_CODE_PREFIX.length());
        // TODO this should be validated to make sure it's even and all digits

        LOGGER.debug(String.format("Code is %s digits long", code.length()));

        // there has to be better way for this
        StringBuilder b = new StringBuilder();
        String[] array = code.split("(?<=\\G.{2})");
        for (String string : array) {
            LOGGER.debug(String.format("Converting %s to %s to %s", string, Integer.parseInt(string) + 45,
                Character.toString(Integer.parseInt(string) + 45)));
            b.append(fromCharCode(Integer.parseInt(string) + 45));
        }

        String result = b.toString();
        LOGGER.debug("Convered code to: " + result);

        return result;
    }

    /**
     * To match the String.fromCharCode from javascript.
     *
     * @param codePoints to pass
     * @return the string
     */
    public static String fromCharCode(int... codePoints) {
        return new String(codePoints, 0, codePoints.length);
    }

    public BufferedImage toBufferedImage(RenderedImage renderedImage) throws IOException {
        // TODO this would be better as streamed without actually writing a file
        File outputfile = File.createTempFile("qr-code-" + System.currentTimeMillis() + "-", ".png");
        outputfile.deleteOnExit();

        ImageIO.write(renderedImage, "png", outputfile);

        // TODO mark this file as to be deleted
        return ImageIO.read(outputfile);
    }

    /**
     * Loads the json provided by the Ontario app. This is checked into source control but can be updated using a
     * different job so it's kept up to date. By storing it here it will allow it to remove the need for an outbound
     * network connection.
     *
     * We are only using the files to pull out the public keys.
     *
     * Location the file is from is https://files.ontario.ca/apps/verify/verifyRulesetON.json
     *
     * @return
     */
    public Map<String, JWKSource<SecurityContext>> loadOntarioTrustKeys() {
        Map<String, JWKSource<SecurityContext>> result = new HashMap<>();

        ObjectMapper mapper = new ObjectMapper();
        try (InputStream in = this.getClass().getClassLoader().getResourceAsStream("verifyRulesetON.json")) {
            JsonNode json = mapper.readTree(in);

            JsonNode publicKeys = json.get("publicKeys");

            // what we are doing here is partially loading the map with jackson so we can pass the string of the "keys"
            // section to the nimbus library that has extra validation on the node
            Map<String, Object> partialMap = mapper.convertValue(publicKeys, new TypeReference<Map<String, Object>>() {
            });
            for (Entry<String, Object> entry : partialMap.entrySet()) {
                // use jackson to convert the keys section of the for that value back into a json string so we can hand
                // it to the library
                String keysAsJson = new ObjectMapper().writeValueAsString(entry.getValue());

                result.put(entry.getKey(), new ImmutableJWKSet<SecurityContext>(JWKSet.parse(keysAsJson)));
            }
        } catch (Exception e) {
            throw new RuntimeException("Could not load the verify rules file to load the public keys", e);
        }

        return result;
    }

    // TODO restructure this method to return have some kind of return or throwing an exception. It's unlikely that a
    // token isn't valid at this point but it's something to check.
    private void validateToken(String accessToken, Map<String, JWKSource<SecurityContext>> trustKeys) {
        try {
            NoClaimsSignedJWT jwt;

            jwt = NoClaimsSignedJWT.parse(accessToken);

            LOGGER.debug("headers: " + jwt.getHeader());
            Payload payload = jwt.getPayload();
            String jsonPayload = NoClaimsSignedJWT.decodePayload(payload.toBase64URL().toString());
            System.out.println("payload extracted: " + jsonPayload);

            String issuer = jwt.getJWTClaimsSet().getIssuer();
            if (!trustKeys.containsKey(issuer)) {
                // this will only get here if a valid token is given that's outside the "circle of trust" of who we
                // allow to sign the tokens
                throw new IllegalArgumentException(
                    String.format("Could not validate token with issuer %s which is not in our list of %s for token %s",
                        issuer, trustKeys.keySet(), accessToken));
            }

            JWKSource<SecurityContext> jwkSet = trustKeys.get(issuer);
            JWSVerificationKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                JWSAlgorithm.ES256, jwkSet);
            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSKeySelector(keySelector);

            // calling this will do the validation
            JWTClaimsSet claimsSet = processor.process(jwt, null);

            LOGGER.debug("Issuer is: " + claimsSet.getIssuer());
            LOGGER.debug("Claims set: " + claimsSet);
        } catch (Exception e) {
            throw new RuntimeException("Could not validate token " + accessToken, e);
        }
    }

}
