/*
 * Copyright (C) 2024 Authlete, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.authlete.sd;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import java.security.Key;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.Test;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


/**
 * This test demonstrates the process of creating a verifiable credential with
 * a binding key embedded, generating a verifiable presentation with a key
 * binding JWT, and verifying the verifiable presentation.
 */
public class VerificationTest
{
    private static String ISSUER_KEY =
            "{\n"
            + "  \"kty\": \"EC\",\n"
            + "  \"alg\": \"ES256\",\n"
            + "  \"crv\": \"P-256\",\n"
            + "  \"kid\": \"BEgmKMrOjukaEXJQU9YkjvZYSMS3Y-1SwTyCmJY_EAQ\",\n"
            + "  \"x\": \"MJFId7cJR2_ul3G-Bb8kaBTpmoTjdE1oNoZakf2PHJw\",\n"
            + "  \"y\": \"4_DClXdM4IP6RgAG_gdBkOs2ADCohqdZFpaCzq2ZN_U\",\n"
            + "  \"d\": \"s0jACpvUNL4nonE8bLo-UW0yPXv3oqbF4skJdakuKxs\"\n"
            + "}\n"
            ;


    private static String WALLET_KEY =
            "{\n"
            + "  \"kty\": \"EC\",\n"
            + "  \"alg\": \"ES256\",\n"
            + "  \"crv\": \"P-256\",\n"
            + "  \"kid\": \"_M6jQowr-8V8myJ9xtXYPmHeYjd1VegmHTxj97vtmHA\",\n"
            + "  \"x\": \"Yiij9HQqyvmSCGbq0walvnelHgIprmcJ0Ah4HzBjJqU\",\n"
            + "  \"y\": \"D9VFlhQ5ZRNp2NWJbTp0UxhmEg0rsuRcmmbj_Iqo1s0\",\n"
            + "  \"d\": \"FoV0kbTmPILo2qFU-4UokJW39e01iSUY4gmkVqzHloE\"\n"
            + "}\n"
            ;


    @Test
    public void test_verification() throws ParseException, JOSEException
    {
        // Create an issuer key for signing the credential JWT, which is
        // to be part of the verifiable credential.
        JWK issuerKey = JWK.parse(ISSUER_KEY);

        // Create a wallet key, which is to be embedded in the credential
        // JWT and used for signing the key binding JWT.
        JWK walletKey = JWK.parse(WALLET_KEY);

        // Create a verifiable credential. The wallet's public key is to
        // be embedded in the credential JWT.
        SDJWT vc = createVC(issuerKey, walletKey.toPublicJWK());

        // Create a verifiable presentation. The wallet's private key is
        // to be used for signing the key binding JWT.
        SDJWT vp = createVP(vc, walletKey);

        // Verify the verifiable presentation. The issuer's public key is
        // used to verify the signature of the credential JWT, while the
        // wallet's public key, embedded in the credential JWT, is used
        // to verify the signature of the key binding JWT.
        verifyVP(vp, issuerKey.toPublicJWK());
    }


    private static SDJWT createVC(JWK issuerKey, JWK walletKey) throws JOSEException, ParseException
    {
        // Normal claims.
        Map<String, Object> claims = Map.of(
                "company", "Authlete"
        );

        // Disclosable user claims.
        List<Disclosure> disclosableClaims = List.of(
                new Disclosure("given_name", "Takahiko"),
                new Disclosure("family_name", "Kawasaki")
        );

        // Create a credential JWT, which is part of an SD-JWT.
        SignedJWT credentialJwt = createCredentialJwt(
                claims, disclosableClaims, issuerKey, walletKey);

        // Create a verifiable credential in the SD-JWT format.
        return new SDJWT(credentialJwt.serialize(), disclosableClaims);
    }


    private static SignedJWT createCredentialJwt(
            Map<String, Object> claims, List<Disclosure> disclosableClaims,
            JWK signingKey, JWK bindingKey) throws ParseException, JOSEException
    {
        // Create the header part of a credential JWT.
        JWSHeader header = createCredentialJwtHeader(signingKey);

        // Create the payload part of a credential JWT.
        Map<String, Object> payload =
                createCredentialJwtPayload(claims, disclosableClaims, bindingKey);

        // Create a credential JWT. (not signed yet)
        SignedJWT jwt = new SignedJWT(header, JWTClaimsSet.parse(payload));

        // Create a signer.
        JWSSigner signer = new DefaultJWSSignerFactory().createJWSSigner(signingKey);

        // Let the signer sign the credential JWT.
        jwt.sign(signer);

        // Return the signed credential JWT.
        return jwt;
    }


    private static JWSHeader createCredentialJwtHeader(JWK signingKey)
    {
        // The signing algorithm.
        JWSAlgorithm alg = JWSAlgorithm.parse(signingKey.getAlgorithm().getName());

        // The key ID.
        String kid = signingKey.getKeyID();

        // Prepare the header part of a credential JWT. The header represents
        // the following:
        //
        //   {
        //      "alg": "<signing-algorithm>",
        //      "kid": "<signing-key-id>",
        //      "typ": "dc+sd-jwt"
        //   }
        //
        // Note that the media type of SD-JWT has been changed from
        // "application/vc+sd-jwt" to "application/dc+sd-jwt". For more details,
        // please refer to the following.
        //
        //   https://datatracker.ietf.org/meeting/121/materials/slides-121-oauth-sessb-sd-jwt-and-sd-jwt-vc-02#page=51
        //   https://github.com/oauth-wg/oauth-sd-jwt-vc/pull/268
        //
        return new JWSHeader.Builder(alg).keyID(kid)
                .type(new JOSEObjectType("dc+sd-jwt"))
                .build();
    }


    private static Map<String, Object> createCredentialJwtPayload(
            Map<String, Object> claims, List<Disclosure> disclosableClaims, JWK bindingKey)
    {
        // Create an SDObjectBuilder instance to prepare the payload part of
        // a credential JWT. "sha-256" is used as a hash algorithm to compute
        // digest values of Disclosures unless a different algorithm is
        // specified by using the SDObjectBuilder(String algorithm) constructor.
        SDObjectBuilder builder = new SDObjectBuilder();

        // vct
        //
        // The type of the verifiable credential. The SD-JWT VC specification
        // requires this claim.
        builder.putClaim("vct", "https://credentials.example.com/identity_credential");

        // iss
        //
        // The identifier of the credential issuer. The SD-JWT VC specification
        // requires this claim.
        builder.putClaim("iss", "https://issuer.example.com");

        // iat
        //
        // The issuance time of the verifiable credential. This claim is optional in
        // the SD-JWT VC specification, but the HAIP specification requires this.
        builder.putClaim("iat", System.currentTimeMillis() / 1000L);

        // cnf
        //
        // The binding key. This claim is optional in the SD-JWT VC specification,
        // but the HAIP specification requires this.
        builder.putClaim("cnf", buildCnfForBindingKey(bindingKey));

        // Put claims, if any.
        if (claims != null)
        {
            // For each claim.
            for (var claim : claims.entrySet())
            {
                // Add the claim.
                builder.putClaim(claim.getKey(), claim.getValue());
            }
        }

        // Put disclosable claims, if any.
        if (disclosableClaims != null)
        {
            // For each disclosable claims.
            for (var claim : disclosableClaims)
            {
                // Add the claim.
                builder.putSDClaim(claim);
            }
        }

        // Create a Map instance that represents the payload part of a
        // credential JWT. The map contains the "_sd" array if disclosable
        // claims have been given.
        return builder.build();
    }


    private static Map<String, Object> buildCnfForBindingKey(JWK bindingKey)
    {
        // Embed the key as the value of the "jwk" property.
        return Map.of("jwk", bindingKey.toJSONObject());
    }


    private static SDJWT createVP(SDJWT vc, JWK walletKey) throws ParseException, JOSEException
    {
        // Select disclosable claims to be passed to verifiers.
        // In this example, only the first one is disclosed.
        List<Disclosure> disclosures = List.of(vc.getDisclosures().get(0));

        // The intended audience of the verifiable presentation.
        List<String> audience = List.of("https://verifier.example.com");

        // Create a binding JWT, which is part of a verifiable presentation.
        SignedJWT bindingJwt = createBindingJwt(vc, disclosures, audience, walletKey);

        // Create a verifiable presentation in the SD-JWT format.
        return new SDJWT(vc.getCredentialJwt(), disclosures, bindingJwt.serialize());
    }


    private static SignedJWT createBindingJwt(
            SDJWT vc, List<Disclosure> disclosures,
            List<String> audience, JWK signingKey) throws ParseException, JOSEException
    {
        // Create the header part of a binding JWT.
        JWSHeader header = createBindingJwtHeader(signingKey);

        // Create the payload part of a binding JWT.
        Map<String, Object> payload =
                createBindingJwtPayload(vc, disclosures, audience);

        // Create a binding JWT. (not signed yet)
        SignedJWT jwt = new SignedJWT(header, JWTClaimsSet.parse(payload));

        // Create a signer.
        JWSSigner signer = new DefaultJWSSignerFactory().createJWSSigner(signingKey);

        // Let the signer sign the binding JWT.
        jwt.sign(signer);

        // Return the signed binding JWT.
        return jwt;
    }


    private static JWSHeader createBindingJwtHeader(JWK signingKey)
    {
        // The signing algorithm.
        JWSAlgorithm alg = JWSAlgorithm.parse(signingKey.getAlgorithm().getName());

        // The key ID.
        String kid = signingKey.getKeyID();

        // Prepare the header part of a binding JWT. The header represents
        // the following:
        //
        //   {
        //      "alg": "<signing-algorithm>",
        //      "kid": "<signing-key-id>",
        //      "typ": "kb+jwt"
        //   }
        //
        return new JWSHeader.Builder(alg).keyID(kid)
                .type(new JOSEObjectType("kb+jwt"))
                .build();
    }


    private static Map<String, Object> createBindingJwtPayload(
            SDJWT vc, List<Disclosure> disclosures, List<String> audience)
    {
        Map<String, Object> payload = new LinkedHashMap<>();

        // iat
        //
        // The issuance time of the binding JWT. The SD-JWT specification
        // requires this claim.
        payload.put("iat", System.currentTimeMillis() / 1000L);

        // aud
        //
        // The intended receiver of the binding JWT. The SD-JWT specification
        // requires this claim.
        payload.put("aud", audience);

        // nonce
        //
        // A random value ensuring the freshness of the signature. The SD-JWT
        // specification requires this claim.
        payload.put("nonce", UUID.randomUUID().toString());

        // sd_hash
        //
        // The base64url-encoded hash value over the Issuer-signed JWT and the
        // selected disclosures. The SD-JWT specification requires this claim.
        payload.put("sd_hash", computeSdHash(vc, disclosures));

        return payload;
    }


    private static String computeSdHash(SDJWT vc, List<Disclosure> disclosures)
    {
        // Compute the SD hash value using the credential JWT in the
        // verifiable credential and the disclosures in the verifiable
        // presentation (not those in the verifiable credential).
        return new SDJWT(vc.getCredentialJwt(), disclosures).getSDHash();
    }


    private static void verifyVP(SDJWT vp, JWK issuerKey) throws ParseException, JOSEException
    {
        // 1. Verify the credential JWT.
        verifyCredentialJwt(vp, issuerKey);

        // 2. Verify the binding JWT.
        verifyBindingJwt(vp);
    }


    private static void verifyCredentialJwt(SDJWT vp, JWK issuerKey) throws ParseException, JOSEException
    {
        // Parse the credential JWT.
        SignedJWT credentialJwt = SignedJWT.parse(vp.getCredentialJwt());

        // Verify the signature of the credential JWT.
        boolean verified = verifySignature(credentialJwt, issuerKey);
        assertTrue("Credential JWT signature verification failed.", verified);

        // There are other aspects to be verified. For example, it should
        // be confirmed that the payload contains the "iss" claim.
        // However, this example code is not intended to be exhaustive.
    }


    private static void verifyBindingJwt(SDJWT vp) throws ParseException, JOSEException
    {
        // Extract the binding key from the payload of the credential JWT.
        JWK bindingKey = extractBindingKey(vp);

        // Parse the binding JWT.
        SignedJWT bindingJwt = SignedJWT.parse(vp.getBindingJwt());

        // Verify the signature of the binding JWT.
        boolean verified = verifySignature(bindingJwt, bindingKey);
        assertTrue("Binding JWT signature verification failed.", verified);

        // Extract the value of the "sd_hash" from the binding JWT.
        String sdHash = bindingJwt.getJWTClaimsSet().getStringClaim("sd_hash");

        // The value of the "sd_hash" in the binding JWT must match
        // the actual SD hash value of the verifiable presentation.
        assertEquals("The sd_hash in the binding JWT is wrong.", vp.getSDHash(), sdHash);

        // There are other aspects to be verified. For example, the "typ"
        // parameter in the JWS header should be confirmed to be "kb+jwt".
        // However, this example code is not intended to be exhaustive.
    }


    @SuppressWarnings("unchecked")
    private static JWK extractBindingKey(SDJWT vp) throws ParseException
    {
        // Parse the credential JWT.
        SignedJWT jwt = SignedJWT.parse(vp.getCredentialJwt());

        // The claims of the credential JWT.
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        // cnf
        Object cnf = claims.getClaim("cnf");

        // jwk
        Object jwk = ((Map<String, Object>)cnf).get("jwk");

        // Convert to a JWK instance.
        return JWK.parse((Map<String, Object>)jwk);
    }


    private static boolean verifySignature(SignedJWT jwt, JWK verificationKey) throws ParseException, JOSEException
    {
        // Create a verifier.
        JWSVerifier verifier = createVerifier(jwt, verificationKey);

        // Verify the signature.
        return jwt.verify(verifier);
    }


    private static JWSVerifier createVerifier(SignedJWT jwt, JWK verificationKey) throws JOSEException
    {
        // Convert the JWK to a PublicKey.
        Key key = convertToPublicKey(verificationKey);

        // Create a verifier.
        return new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), key);
    }


    private static PublicKey convertToPublicKey(JWK jwk) throws JOSEException
    {
        // The "kty" (key type) of the JWK.
        KeyType keyType = jwk.getKeyType();

        // EC
        if (KeyType.EC.equals(keyType))
        {
            return jwk.toECKey().toPublicKey();
        }
        // RSA
        else if (KeyType.RSA.equals(keyType))
        {
            return jwk.toRSAKey().toPublicKey();
        }
        // OKP
        else if (KeyType.OKP.equals(keyType))
        {
            return jwk.toOctetKeyPair().toPublicKey();
        }
        else
        {
            throw new JOSEException(String.format(
                    "The key type '%s' is not supported.", keyType));
        }
    }
}
