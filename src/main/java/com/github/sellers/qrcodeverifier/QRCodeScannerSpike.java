package com.github.sellers.qrcodeverifier;

import java.awt.image.BufferedImage;
import java.awt.image.RenderedImage;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.zip.Inflater;

import javax.imageio.ImageIO;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.graphics.PDXObject;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DeflateUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 *
 * @author sellersj
 */
public class QRCodeScannerSpike {

    private static final Logger LOGGER = LoggerFactory.getLogger(QRCodeScannerSpike.class);

    /** The standard path for the key store. Required to be passed if using a proxy. */
    private static final String WELL_KNOWN_JWKS_PATH = "/.well-known/jwks.json";

    private static final String QR_CODE_PREFIX = "shc:/";

    private int count = 0;

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

    public void readFromPdfs() throws Exception {

        // Path where the QR code is saved
        File file = new File(System.getProperty("user.home") + "/Downloads/example-covid-generated.pdf");
        List<String> qrCodesFromPdf = getQrCodesFromPdf(file);
        for (String qrCode : qrCodesFromPdf) {
            String rawJwt = smartQrCodeToJwt(qrCode);
            validateToken(rawJwt);
        }
    }

    private List<String> getQrCodesFromPdf(File file) {
        List<String> result = new ArrayList<>();

        try {
            PDDocument pdDoc = PDDocument.load(file);

            List<RenderedImage> images = getImagesFromPDF(pdDoc);
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

    // TODO consider changing a parser that implements JWTParser
    private String smartQrCodeToJwt(String qrCode) throws Exception {
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
        // TODO this would be better as a temp or totally streamed without actually writing a file
        File outputfile = new File("target/saved" + count++ + ".png");
        ImageIO.write(renderedImage, "png", outputfile);

        // TODO mark this file as to be deleted
        return ImageIO.read(outputfile);
    }

    /**
     * Takes a base64 string of a compressed string that does not have any header info on it and
     * converts it into a string.
     * 
     * @param payload base64 string of compressed text
     * @return the decompressed string
     * @throws Exception
     */
    private String decodePayload(String payload) {
        try {
            byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
            byte[] decompressed = DeflateUtils.decompress(decodedBytes);
            return new String(decompressed, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Could not decompress payload " + payload, e);
        }
    }

    public static void main(String[] args) throws Exception {
        QRCodeScannerSpike spike = new QRCodeScannerSpike();
        spike.readFromPdfs();
    }

    private void nimbusExample2() throws Exception {
        // The access token to validate, typically submitted with a HTTP header like
        // Authorization: Bearer eyJraWQiOiJDWHVwIiwidHlwIjoiYXQrand0IiwiYWxnIjoi...
        String accessToken = "eyJraWQiOiJDWHVwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJib2IiLCJzY"
            + "3AiOlsib3BlbmlkIiwiZW1haWwiXSwiY2xtIjpbIiFCZyJdLCJpc3MiOiJodHRwczpcL1wvZGVtby5jM"
            + "mlkLmNvbVwvYzJpZCIsImV4cCI6MTU3MTMxMjAxOCwiaWF0IjoxNTcxMzExNDE4LCJ1aXAiOnsiZ3Jvd"
            + "XBzIjpbImFkbWluIiwiYXVkaXQiXX0sImp0aSI6ImJBT1BiNWh5TW80IiwiY2lkIjoiMDAwMTIzIn0.Q"
            + "hTAdJK8AbdJJhQarjOz_qvAINQeWJCIYSROVaeRpBfaOrTCUy5gWRf8xrpj1DMibdHwQGPdht3chlAC8"
            + "LGbAorEu0tLLcOwKl4Ql-o30Tdd5QhjNb6PndOY89NbQ1O6cdOZhvV4XB-jUAXi3nDgCw3zvIn2348Va"
            + "2fOAzxUvRs2OGsEDl5d9cmL3e68YqSh7ss12y9oBDyEyz8Py7dtXgt6Tg67n9WlEBG0r4KloGDBdbCCZ"
            + "hlEyURkHaE-3nUcjwd-CEVeqWPO0bsLhwto-80j8BtsfD649GnvaMb9YdbdYhTTs-MkRUQpQIZT0s9oK"
            + "uzKayvZhk0c_0FoSeW7rw";

        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // Set the required "typ" header "at+jwt" for access tokens issued by the
        // Connect2id server, may not be set by other servers
        jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
        // object caches the retrieved keys to speed up subsequent look-ups and can
        // also handle key-rollover
        JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL("https://demo.c2id.com/jwks.json"));

        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);

        // Set the required JWT claims for access tokens issued by the Connect2id
        // server, may differ with other servers
        jwtProcessor.setJWTClaimsSetVerifier(
            new DefaultJWTClaimsVerifier(new JWTClaimsSet.Builder().issuer("https://demo.c2id.com/c2id").build(),
                new HashSet<>(Arrays.asList("sub", "iat", "exp", "scp", "cid", "jti"))));

        // Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, ctx);

        // Print out the token claims set
        System.out.println(claimsSet.toJSONObject());
    }

    private void validateToken(String accessToken) throws Exception {
        // SignedJWT signedJWT = SignedJWT.parse(accessToken);
        NoClaimsSignedJWT jwt = NoClaimsSignedJWT.parse(accessToken);

        System.out.println("headers: " + jwt.getHeader());
        Payload payload = jwt.getPayload();
        // CompressionAlgorithm jsonPayload = new CompressionAlgorithm(payload.toString());
        String jsonPayload = decodePayload(payload.toBase64URL().toString());
        System.out.println("payload extracted: " + jsonPayload);

        // jwt.verify(null)
        // get this from the header? Check standard if this is hard coded
        RemoteJWKSet<?> jwkSet = new RemoteJWKSet<>(
            new URL("https://prd.pkey.dhdp.ontariohealth.ca" + WELL_KNOWN_JWKS_PATH));
        JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.ES256, jwkSet);
        DefaultJWTProcessor processor = new DefaultJWTProcessor();
        processor.setJWSKeySelector(keySelector);

        // calling this will do the validation
        JWTClaimsSet claimsSet = processor.process(jwt, null);

        System.out.println("Claims set: " + claimsSet);

        // System.out.println("claim set: " + jwt.getJWTClaimsSet());
    }

}
