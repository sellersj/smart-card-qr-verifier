package com.github.sellers.qrcodeverifier;

import java.text.ParseException;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class NoClaimsSignedJWT extends SignedJWT {

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
        return JWTClaimsSet.parse("{}");
    }

}
