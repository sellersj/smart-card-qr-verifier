package com.github.sellers.qrcodeverifier;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.DeflateUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Work around since the library doesn't do decompression on payloads for JWT's. Created a ticket
 * https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/464/consider-decompression-of-payload-if-it-is
 *
 * @author SellersJ
 *
 */
public class NoClaimsSignedJWT extends SignedJWT {

    /** */
    private static final long serialVersionUID = 1L;

    public NoClaimsSignedJWT(final JWSHeader header, final JWTClaimsSet claimsSet) {
        super(header, claimsSet);
    }

    public NoClaimsSignedJWT(final Base64URL firstPart, final Base64URL secondPart, final Base64URL thirdPart)
        throws ParseException {
        super(firstPart, secondPart, thirdPart);
    }

    public static NoClaimsSignedJWT parse(final String s) throws ParseException {

        Base64URL[] parts = JOSEObject.split(s);

        if (parts.length != 3) {
            throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
        }

        return new NoClaimsSignedJWT(parts[0], parts[1], parts[2]);
    }

    @Override
    public JWTClaimsSet getJWTClaimsSet() throws ParseException {
        // TODO ignore this untl we can figure out if it's needed for signature check
        String jsonPayload = decodePayload(getPayload().toBase64URL().toString());
        return JWTClaimsSet.parse(jsonPayload);
    }

    /**
     * TODO figure out where we should have this. Ideally we could just override the Payload method but not sure how to
     * do that yet
     *
     * Takes a base64 string of a compressed string that does not have any header info on it and converts it into a
     * string.
     *
     * @param payload base64 string of compressed text
     * @return the decompressed string
     * @throws Exception
     */
    public static String decodePayload(String payload) {
        try {
            byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
            byte[] decompressed = DeflateUtils.decompress(decodedBytes);
            return new String(decompressed, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Could not decompress payload " + payload, e);
        }
    }

}
