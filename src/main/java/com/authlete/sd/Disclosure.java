/*
 * Copyright (C) 2023 Authlete, Inc.
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
import static com.authlete.sd.SDUtility.computeDigest;
import static com.authlete.sd.SDUtility.fromBase64url;
import static com.authlete.sd.SDUtility.fromJson;
import static com.authlete.sd.SDUtility.fromUTF8Bytes;
import static com.authlete.sd.SDUtility.generateRandomBytes;
import static com.authlete.sd.SDUtility.isReservedKey;
import static com.authlete.sd.SDUtility.toBase64url;
import static com.authlete.sd.SDUtility.toJson;
import static com.authlete.sd.SDUtility.toUTF8Bytes;
import java.util.List;
import java.util.Objects;


/**
 * A class that represents the "Disclosure" defined in the SD-JWT specification.
 *
 * <p>
 * Instances of this class are immutable.
 * </p>
 *
 * <p>
 * <b>Example 1:</b>
 * </p>
 *
 * <blockquote>
 * <pre>
 * // Parameters for the constructor.
 * String salt       = "_26bc4LT-ac6q2KI6cBW5es";
 * String claimName  = "family_name";
 * Object claimValue = "Möbius";
 *
 * // Create a Disclosure instance with the parameters.
 * Disclosure disclosure = new Disclosure(salt, claimName, claimValue);
 *
 * // Get the string representation of the disclosure.
 * String dc = disclosure.getDisclosure(); // or disclosure.toString();
 *
 * // dc -> "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd"
 * </pre>
 * </blockquote>
 *
 * <p>
 * <b>Example 2:</b>
 * </p>
 *
 * <blockquote>
 * <pre>
 * // Parse a string representation of disclosure.
 * Disclosure disclosure = Disclosure.parse(
 *     "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0");
 *
 * // Compute the digest of the disclosure with the default hash algorithm ("sha-256").
 * String digest = disclosure().digest(); // or disclosure.digest("sha-256");
 *
 * // digest -> "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY"
 * </pre>
 * </blockquote>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/"
 *      >Selective Disclosure for JWTs (SD-JWT)</a>
 *
 * @since 1.0
 */
public class Disclosure
{
    private final String salt;
    private final String claimName;
    private final Object claimValue;
    private final String json;
    private final String disclosure;
    private final String defaultDigest;
    private final int    hashCode;


    /**
     * Constructor with a pair of claim name and claim value. A salt is
     * randomly generated.
     *
     * @param claimName
     *         A claim name. Must not be null.
     *
     * @param claimValue
     *         A claim value. May be null.
     *
     * @throws IllegalArgumentException
     *         The given claim name is null.
     */
    public Disclosure(String claimName, Object claimValue)
    {
        this(generateSalt(), claimName, claimValue);
    }


    /**
     * Constructor with a salt and a pair of claim name and claim value.
     *
     * @param salt
     *         A salt. Must not be null. It is recommended that the salt have
     *         128-bit or higher entropy and be base64url-encoded.
     *
     * @param claimName
     *         A claim name. Must not be null.
     *
     * @param claimValue
     *         A claim value. May be null.
     *
     * @throws IllegalArgumentException
     *         The given salt and/or claim name are null.
     */
    public Disclosure(String salt, String claimName, Object claimValue)
    {
        this(salt, claimName, claimValue, null, null);
    }


    /**
     * A private constructor for the implementation of the
     * {@link #parse(String)} method.
     */
    private Disclosure(
            String salt, String claimName, Object claimValue,
            String json, String disclosure)
    {
        // If a salt is not given.
        if (salt == null)
        {
            throw new IllegalArgumentException("'salt' is missing.");
        }

        // If a claim name is not given.
        if (claimName == null)
        {
            throw new IllegalArgumentException("'claimName' is missing.");
        }

        // If a JSON representation is not given.
        if (json == null)
        {
            // [ salt, claimName, claimValue ]
            json = toJson(List.of(salt, claimName, claimValue));
        }

        // If a disclosure is not given.
        if (disclosure == null)
        {
            // Convert the JSON to UTF-8 bytes, then base64url-encode the bytes.
            disclosure = toBase64url(toUTF8Bytes(json));
        }

        this.salt          = salt;
        this.claimName     = claimName;
        this.claimValue    = claimValue;
        this.json          = json;
        this.disclosure    = disclosure;
        this.defaultDigest = computeDigest(DEFAULT_HASH_ALGORITHM, disclosure);
        this.hashCode      = Objects.hash(getClass(), getDisclosure());
    }


    /**
     * Get the salt.
     *
     * @return
     *         The salt.
     */
    public String getSalt()
    {
        return salt;
    }


    /**
     * Get the claim name.
     *
     * @return
     *         The claim name.
     */
    public String getClaimName()
    {
        return claimName;
    }


    /**
     * Get the claim value.
     *
     * @return
     *         The claim value.
     */
    public Object getClaimValue()
    {
        return claimValue;
    }


    /**
     * Get the JSON representation of this disclosure. It is a JSON array
     * with three elements. They are the salt, the claim name and the claim
     * value.
     *
     * @return
     *         The JSON representation of this disclosure.
     */
    public String getJson()
    {
        return json;
    }


    /**
     * Get the disclosure as a string.
     *
     * @return
     *         The disclosure as a string.
     */
    public String getDisclosure()
    {
        return disclosure;
    }


    /**
     * Get the digest of this disclosure computed with the default hash
     * algorithm ("{@code sha-256}").
     */
    private String getDefaultDigest()
    {
        return defaultDigest;
    }


    /**
     * Get the base64url-encoded digest of this disclosure computed with the
     * default hash algorithm ("{@code sha-256}").
     *
     * <p>
     * The digest value with the default hash algorithm is computed on instance
     * creation and the result is cached. This {@code digest()} method always
     * returns the cached value. Therefore, calling this method is lightweight.
     * </p>
     *
     * @return
     *         The base64url-encoded digest of this disclosure computed with
     *         the default hash algorithm ("{@code sha-256}").
     */
    public String digest()
    {
        return getDefaultDigest();
    }


    /**
     * Get the base64url-encoded digest of this disclosure computed with the
     * specified hash algorithm.
     *
     * @param hashAlgorithm
     *         A hash algorithm. Must not be null. If the given hash algorithm
     *         is equal to the default hash algorithm ("{@code sha-256}"),
     *         the cached digest value is returned (cf. {@link #digest()}).
     *
     * @return
     *         The base64url-encoded digest of this disclosure computed with
     *         the specified hash algorithm.
     *
     * @see <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg"
     *      >IANA: Named Information Hash Algorithm Registry</a>
     */
    public String digest(String hashAlgorithm)
    {
        if (hashAlgorithm == null)
        {
            throw new IllegalArgumentException("'hashAlgorithm' is missing.");
        }

        if (DEFAULT_HASH_ALGORITHM.equalsIgnoreCase(hashAlgorithm))
        {
            return getDefaultDigest();
        }

        return computeDigest(hashAlgorithm, getDisclosure());
    }


    /**
     * Get the string representation of this instance is returned, which is
     * the disclosure in the base64url format.
     *
     * @return
     *         The disclosure in the base64url format.
     */
    @Override
    public String toString()
    {
        return getDisclosure();
    }


    @Override
    public int hashCode()
    {
        return hashCode;
    }


    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }

        if (getClass() != obj.getClass())
        {
            return false;
        }

        Disclosure that = (Disclosure)obj;

        return getDisclosure().equals(that.getDisclosure());
    }


    /**
     * Parse the given string as a disclosure.
     *
     * @param disclosure
     *         A string representation of disclosure. If null is given, null
     *         is returned.
     *
     * @return
     *         A {@link Disclosure} instance created as a result of parsing
     *         the input string.
     *
     * @throws IllegalArgumentException
     *         (1) The given string is not base64url-encoded.
     *         (2) The base64url-decoded value of the given string is not a
     *             valid UTF-8 byte sequence.
     *         (3) The JSON that the given string represents fails to be parsed
     *             as a JSON array.
     *         (4) The size of the JSON array is not 3.
     *         (5) The first and/or second elements of the JSON array are not
     *             JSON strings.
     *         (6) The claim name (the second element in the JSON array) is a
     *             key reserved by the SD-JWT specification.
     */
    public static Disclosure parse(String disclosure)
    {
        if (disclosure == null)
        {
            return null;
        }

        // Base64url-decode the input to bytes, then build a string from the bytes.
        String json = fromUTF8Bytes(fromBase64url(disclosure));

        // Parse the string as a JSON array.
        List<?> elements = fromJson(json, List.class);

        if (elements == null || elements.size() != 3)
        {
            throw new IllegalArgumentException("Not a JSON array having 3 elements.");
        }

        Object first = elements.get(0);
        if (!(first instanceof String))
        {
            throw new IllegalArgumentException("The first element (salt) is not a string.");
        }

        Object second = elements.get(1);
        if (!(second instanceof String))
        {
            throw new IllegalArgumentException("The second element (claimName) is not a string.");
        }

        String salt       = (String)first;
        String claimName  = (String)second;
        Object claimValue = elements.get(2);

        if (isReservedKey(claimName))
        {
            throw new IllegalArgumentException(
                    String.format("The claim name ('%s') is a reserved key.", claimName));
        }

        return new Disclosure(salt, claimName, claimValue, json, disclosure);
    }


    /**
     * Generate a random salt in the base64url format.
     */
    private static String generateSalt()
    {
        // Base64url-encoded random value with 128-bit entropy.
        return toBase64url(generateRandomBytes(16));
    }
}
