package com.github.sellers.qrcodeverifier;

import java.awt.image.BufferedImage;
import java.awt.image.RenderedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.imageio.ImageIO;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.graphics.PDXObject;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;

import com.google.zxing.BinaryBitmap;
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

    // Function to read the QR file
    public static String readQR(String path, String charset, Map hashMap)
        throws FileNotFoundException, IOException, NotFoundException {
        BinaryBitmap binaryBitmap = new BinaryBitmap(
            new HybridBinarizer(new BufferedImageLuminanceSource(ImageIO.read(new FileInputStream(path)))));

        Result result = new MultiFormatReader().decode(binaryBitmap);

        return result.getText();
    }

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

            result = new MultiFormatReader().decode(bitmap);
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
            }
        }
    }

    public BufferedImage toBufferedImage(RenderedImage renderedImage) throws Exception {
        // TODO this would be better as a temp
        File outputfile = new File("target/saved.png");
        ImageIO.write(renderedImage, "png", outputfile);

        // TODO mark this file as to be deleted
        return ImageIO.read(outputfile);
    }

    public static void main(String[] args) throws Exception {
        QRCodeScannerSpike spike = new QRCodeScannerSpike();
        spike.readFromPdfs();
    }

}
