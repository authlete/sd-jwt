/*
 * Copyright (C) 2023-2024 Authlete, Inc.
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


import static com.authlete.sd.SDConstants.DEFAULT_HASH_ALGORITHM;
import static com.authlete.sd.SDConstants.KEY_SD_ALG;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * A class that represents SD-JWT.
 *
 * <p>
 * Instances of this class are immutable. References to {@link Disclosure}
 * instances given to the constructor are internally copied and the
 * {@link #getDisclosures()} method returns the copied list as an
 * unmodifiable list.
 * </p>
 *
 * @since 1.2
 */
public class SDJWT
{
    private static final String DELIMITER = "~";


    private final String credentialJwt;
    private final List<Disclosure> disclosures;
    private final String bindingJwt;
    private final String serialized;
    private final String hashAlgorithm;
    private final String sdHash;


    /**
     * Constructor with a credential JWT and disclosures.
     *
     * @param credentialJwt
     *         A credential JWT. Must not be null.
     *
     * @param disclosures
     *         Disclosures. May be null.
     */
    public SDJWT(String credentialJwt, Collection<Disclosure> disclosures)
    {
        this(credentialJwt, disclosures, /* bindingJwt */ null);
    }


    /**
     * Constructor with a credential JWT, disclosures and a binding JWT.
     *
     * @param credentialJwt
     *         A credential JWT. Must not be null.
     *
     * @param disclosures
     *         Disclosures. May be null.
     *
     * @param bindingJwt
     *         A binding JWT. May be null.
     */
    public SDJWT(String credentialJwt, Collection<Disclosure> disclosures, String bindingJwt)
    {
        // Credential JWT
        this.credentialJwt = credentialJwt;

        // Disclosures
        this.disclosures = (disclosures == null)
                ? Collections.unmodifiableList(Collections.emptyList())
                : disclosures.stream()
                    .filter(Objects::nonNull)
                    .collect(Collectors.toUnmodifiableList());

        // Binding JWT
        this.bindingJwt = bindingJwt;

        // The string representation of this SD-JWT.
        this.serialized = serialize(credentialJwt, this.disclosures, bindingJwt);

        // The hash algorithm used by the disclosures.
        this.hashAlgorithm = determineHashAlgorithm(credentialJwt);

        // The SD hash value.
        this.sdHash = computeSdHash(credentialJwt, this.disclosures, hashAlgorithm);
    }


    /**
     * Get the string representation of this SD-JWT.
     *
     * <p>
     * The returned string has the following format.
     * </p>
     *
     * <pre>
     * {Credential-JWT}~{Disclosure1}~...~{DisclosureN}~[{Binding-JWT}]
     * </pre>
     *
     * @return
     *         The string representation of this SD-JWT.
     */
    @Override
    public String toString()
    {
        return serialized;
    }


    /**
     * Get the credential JWT, which is the JWT placed at the head of SD-JWT.
     *
     * @return
     *         The credential JWT.
     */
    public String getCredentialJwt()
    {
        return credentialJwt;
    }


    /**
     * Get the list of disclosures.
     *
     * @return
     *         The list of disclosures. The returned list is always non-null
     *         and unmodifiable.
     */
    public List<Disclosure> getDisclosures()
    {
        return disclosures;
    }


    /**
     * Get the binding JWT, which is the JWT placed optionally at the end of
     * SD-JWT.
     *
     * @return
     *         The binding JWT. May be null.
     */
    public String getBindingJwt()
    {
        return bindingJwt;
    }


    /**
     * Get the hash algorithm used for the disclosures.
     *
     * <p>
     * This method returns the value of the {@code "_sd_alg"} claim in the
     * credential JWT. If the claim is not available, {@code "sha-256"}
     * (the default hash algorithm) is returned.
     * </p>
     *
     * @return
     *         The hash algorithm.
     *
     * @since 1.5
     */
    public String getHashAlgorithm()
    {
        return hashAlgorithm;
    }


    /**
     * Get the SD hash value that can be used as the value of the {@code "sd_hash"}
     * claim in a key binding JWT. If this SD-JWT includes a key binding JWT, the
     * value of the {@code "sd_hash"} claim in the key binding JWT must match the
     * value returned by this method.
     *
     * <p>
     * The input for the hash computation is the serialized form of this SD-JWT,
     * excluding the key binding JWT, which may be appended at the end.
     * </p>
     *
     * <p>
     * The algorithm for the hash computation is the same as used for disclosures.
     * This algorithm is provided by the {@link #getHashAlgorithm()} method.
     * </p>
     *
     * <p>
     * The returned value is base64url-encoded as required by the SD-JWT
     * specification.
     * </p>
     *
     * @return
     *         The SD hash value computed using the credential JWT and disclosures
     *         of this SD-JWT.
     *
     * @since 1.5
     */
    public String getSDHash()
    {
        return sdHash;
    }


    /**
     * Parse the given string as SD-JWT.
     *
     * <p>
     * The expected format of the input string is as follows.
     * </p>
     *
     * <pre>
     * {Credential-JWT}~{Disclosure1}~...~{DisclosureN}~[{Binding-JWT}]
     * </pre>
     *
     * @param input
     *         A string representing SD-JWT. If null is given, null is
     *         returned.
     *
     * @return
     *         An {@code SDJWT} instance created as a result of parsing the
     *         input string.
     */
    public static SDJWT parse(String input)
    {
        if (input == null)
        {
            return null;
        }

        // <Credential-JWT>~<Disclosure1>~...~<DisclosureN>~
        // <Credential-JWT>~<Disclosure1>~...~<DisclosureN>~<Binding-JWT>
        String[] elements = input.split(DELIMITER, -1);

        // The index of the last element.
        int lastIndex = elements.length - 1;

        // Make sure that all elements except the last one are not empty.
        for (int i = 0; i < lastIndex; i++)
        {
            // If the element is an empty string.
            if (elements[i].length() == 0)
            {
                throw new IllegalArgumentException("The SD-JWT is malformed.");
            }
        }

        if (elements.length < 2)
        {
            throw new IllegalArgumentException("The SD-JWT is malformed.");
        }

        // The credential JWT
        String credentialJwt = elements[0];

        // The binding JWT
        String bindingJwt = input.endsWith(DELIMITER) ? null : elements[lastIndex];

        // Disclosures
        List<Disclosure> disclosures;

        try
        {
            // Parse elements in between the credential JWT and
            // the optional binding JWT as Disclosures.
            disclosures = Arrays.asList(elements)
                    .subList(1, lastIndex)
                    .stream()
                    .map(Disclosure::parse)
                    .collect(Collectors.toList());
        }
        catch (Exception cause)
        {
            throw new IllegalArgumentException("Failed to parse disclosures.", cause);
        }

        return new SDJWT(credentialJwt, disclosures, bindingJwt);
    }


    private static String serialize(
            String credentialJwt, List<Disclosure> disclosures, String bindingJwt)
    {
        // Credential-JWT, Disclosure1, Disclosure2, ..., DisclosureN
        Stream<String> stream = Stream.concat(
                Stream.of(credentialJwt),
                disclosures.stream().map(Disclosure::getDisclosure));

        // Credential-JWT, Disclosure1, Disclosure2, ..., DisclosureN, Binding-JWT
        stream = Stream.concat(
                stream,
                Stream.of(bindingJwt != null ? bindingJwt : ""));

        // Build a string representation of SD-JWT.
        return stream.collect(Collectors.joining(DELIMITER));
    }


    @SuppressWarnings("unchecked")
    private static String determineHashAlgorithm(String credentialJwt)
    {
        // If a credential JWT is not specified. (This is abnormal.)
        if (credentialJwt == null)
        {
            return DEFAULT_HASH_ALGORITHM;
        }

        // If the credential JWT does not have the payload. (This is abnormal.)
        String[] fields = credentialJwt.split("\\.");
        if (fields.length < 2)
        {
            return DEFAULT_HASH_ALGORITHM;
        }

        Map<String, Object> payload;

        try
        {
            // Decode the second field of the credential JWT with base64url.
            byte[] decoded = SDUtility.fromBase64url(fields[1]);

            // The decoded field should form a string.
            String string = new String(decoded, StandardCharsets.UTF_8);

            // The string should be a JSON object.
            payload = SDUtility.fromJson(string, Map.class);
        }
        catch (RuntimeException cause)
        {
            // The payload part is malformed.
            return DEFAULT_HASH_ALGORITHM;
        }

        // The value of the "_sd_alg" claim in the payload.
        Object alg = payload.get(KEY_SD_ALG);

        // If the payload does not contain the "_sd_alg" claim or
        // its value is not a string.
        if (!(alg instanceof String))
        {
            return DEFAULT_HASH_ALGORITHM;
        }

        // The algorithm specified by the "_sd_alg" claim.
        return (String)alg;
    }


    private static String computeSdHash(
            String credentialJwt, List<Disclosure> disclosures, String algorithm)
    {
        // Build the input for hash computation.
        String input = serialize(credentialJwt, disclosures, null);

        // Compute the hash value of the input.
        return SDUtility.computeDigest(algorithm, input);
    }
}
