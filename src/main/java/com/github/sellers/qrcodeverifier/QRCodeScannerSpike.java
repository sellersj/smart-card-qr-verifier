package com.github.sellers.qrcodeverifier;

import java.awt.image.BufferedImage;
import java.awt.image.RenderedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
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

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

/**
 * 
 * @author sellersj
 */
public class QRCodeScannerSpike {

    private static final Logger LOGGER = LoggerFactory.getLogger(QRCodeScannerSpike.class);

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
            // log.error("QRCode not found", e);
            System.err.println("QR Code not found");
        }

        // if we are here, it didn't work.
        // TODO change this to be an optional
        return null;
    }

    public void readFromPdfs() throws Exception {

        // Path where the QR code is saved
        File file = new File(System.getProperty("user.home") + "/Downloads/example-covid-generated.pdf");
        PDDocument pdDoc = PDDocument.load(file);

        List<RenderedImage> images = getImagesFromPDF(pdDoc);
        System.out.println(String.format("Found %s images", images.size()));
        for (RenderedImage renderedImage : images) {
            // System.out.println(renderedImage);

            String result = decodeQRCode(toBufferedImage(renderedImage));
            if (null != result) {
                System.out.println(result);
                extractValues(result);
            }
        }
    }

    private void extractValues(String qrCode) throws Exception {
        String prefix = "shc:/";
        if (!qrCode.startsWith(prefix)) {
            System.err.println("this is not a valid qr code");
        } else {
            String code = qrCode.substring(prefix.length());
            // TODO this should be validated to make sure it's even and all digits

            System.out.println(String.format("Code is %s digits long", code.length()));

            // there has to be better way for this
            StringBuilder b = new StringBuilder();
            String[] array = code.split("(?<=\\G.{2})");
            for (String string : array) {
                LOGGER.debug(String.format("Converting %s to %s to %s", string, Integer.parseInt(string) + 45,
                    Character.toString(Integer.parseInt(string) + 45)));
                b.append(fromCharCode(Integer.parseInt(string) + 45));
            }

            System.out.println("code is " + code);
            System.out.println("b is " + b.toString());

            String[] splits = b.toString().split("\\.");
            System.out.println("there was " + splits.length + " sections");
            for (String string : splits) {
                System.out.println(String.format("Section is %s digits long", string.length()));
                System.out.println(string);
            }

            // TODO throw exception if the number of arguments is bad

            //

            String header = getHeader(splits[0]);
            System.out.println("Decoded header: " + header);

            String payload = decodePayload(splits[1]);
            System.out.println("Decoded payload: " + payload);

            String signature = splits[2];
            System.out.println("Raw signature: " + signature);

            // TODO figure out if we can use the JWS token to validate this
            // useAuth0Library(b.toString());
        }
    }

    private String getHeader(String rawHeader) {
        byte[] decodedBytes = Base64.getUrlDecoder().decode(rawHeader);
        String decodedString = new String(decodedBytes);

        return decodedString;
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

    private void useAuth0Library(String token) {
        try {

            Algorithm algorithm = Algorithm.HMAC256("secret");
            JWTVerifier verifier = JWT.require(algorithm)//
                .withIssuer("auth0") //
                .build();
            // DecodedJWT jwt = verifier.verify(token);
            // TODO verify it, but right now just decode it
            DecodedJWT jwt = JWT.decode(token);

            System.out.println("Auth0 library jst token is: " + jwt);
        } catch (JWTVerificationException exception) {
            System.err.println("Auth0 library could not decrpty token: " + token);
            exception.printStackTrace();
        }
    }

    public BufferedImage toBufferedImage(RenderedImage renderedImage) throws Exception {
        // TODO this would be better as a temp or totally streamed without actually writing a file
        File outputfile = new File("target/saved" + count++ + ".png");
        ImageIO.write(renderedImage, "png", outputfile);

        // TODO mark this file as to be deleted
        return ImageIO.read(outputfile);
    }

    private String decodePayload(String payload) throws Exception {
        byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decodedBytes);

        // Decompress the bytes but ignore headers
        Inflater decompresser = new Inflater(true);
        decompresser.setInput(byteBuffer);

        // byte[] result = new byte[10000];
        // TODO this needs to be better to propertly buffer the size of the payload
        ByteBuffer result = ByteBuffer.allocate(240000);

        int resultLength = decompresser.inflate(result);
        decompresser.end();

        // Decode the bytes into a String
        // String outputString = new String(result, 0, resultLength, "UTF-8");

        String outputString = new String(result.array(), StandardCharsets.UTF_8);
        return outputString;
    }

    public static void main(String[] args) throws Exception {
        QRCodeScannerSpike spike = new QRCodeScannerSpike();
        spike.readFromPdfs();
    }

}
