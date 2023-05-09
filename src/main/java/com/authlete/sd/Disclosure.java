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
 * <pre style="border:1px solid black; padding:1em;">
 * <span style="color:darkgreen;">// Parameters for the constructor.</span>
 * String salt       = <span style="color:brown;">"_26bc4LT-ac6q2KI6cBW5es"</span>;
 * String claimName  = <span style="color:brown;">"family_name"</span>;
 * Object claimValue = <span style="color:brown;">"Möbius"</span>;
 *
 * <span style="color:darkgreen;">// Create a Disclosure instance with the parameters.</span>
 * Disclosure disclosure =
 *     new Disclosure(salt, claimName, claimValue);
 *
 * <span style="color:darkgreen;">// Get the string representation of the disclosure.
 * // disclosure.toString() returns the same result.</span>
 * String dc = disclosure.getDisclosure();
 *
 * <span style="color:darkgreen;">// dc -> "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd"</span>
 * </pre>
 * </blockquote>
 *
 * <p>
 * <b>Example 2:</b>
 * </p>
 *
 * <blockquote>
 * <pre style="border:1px solid black; padding:1em;">
 * <span style="color:darkgreen;">// Parse a string representation of disclosure.</span>
 * Disclosure disclosure = Disclosure.parse(
 *     <span style="color:brown;">"WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"</span>);
 *
 * <span style="color:darkgreen;">// Compute the digest of the disclosure with the default
 * // hash algorithm ("sha-256"). disclosure.digest("sha-256")
 * // returns the same result.</span>
 * String digest = disclosure().digest();
 *
 * <span style="color:darkgreen;">// digest -> "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY"</span>
 * </pre>
 * </blockquote>
 *
 * <p>
 * <b>Example 3:</b>
 * </p>
 *
 * <blockquote>
 * <pre style="border:1px solid black; padding:1em;">
 * <span style="color:darkgreen;">// Parameters for the constructor.</span>
 * String salt       = <span style="color:brown;">"_26bc4LT-ac6q2KI6cBW5es"</span>;
 * String claimName  = <span style="color:brown;">"my_array"</span>;
 * int    claimIndex = 0;
 * Object claimValue = <span style="color:brown;">"my_array_element_at_index_0"</span>;
 *
 * <span style="color:darkgreen;">// Create a Disclosure instance representing an array element.</span>
 * Disclosure disclosure =
 *     new Disclosure(salt, claimName, claimIndex, claimValue);
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
    private final int    claimIndex;
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
        this(salt, claimName, -1, claimValue, null, null);
    }


    /**
     * Constructor with a claim name (an array name), a claim index (an array
     * index) and a claim value. A salt is randomly generated.
     *
     * <p>
     * The purpose of this constructor is to create a disclosure for an array
     * element.
     * </p>
     *
     * @param claimName
     *         A claim name (an array name). Must not be null.
     *
     * @param claimIndex
     *         A claim index (an array index). For an array element, 0 or a
     *         positive integer should be given. If a negative integer is
     *         given, the disclosure created by this constructor will not
     *         represent an array element.
     *
     * @param claimValue
     *         A claim value. May be null.
     *
     * @throws IllegalArgumentException
     *         The given claim name is null.
     *
     * @since 1.1
     */
    public Disclosure(String claimName, int claimIndex, Object claimValue)
    {
        this(generateSalt(), claimName, claimIndex, claimValue);
    }


    /**
     * Constructor with a salt, a claim name (an array name), a claim index
     * (an array index) and a claim value.
     *
     * @param salt
     *         A salt. Must not be null. It is recommended that the salt have
     *         128-bit or higher entropy and be base64url-encoded.
     *
     * @param claimName
     *         A claim name (an array name). Must not be null.
     *
     * @param claimIndex
     *         A claim index (an array index). For an array element, 0 or a
     *         positive integer should be given. If a negative integer is
     *         given, the disclosure created by this constructor will not
     *         represent an array element.
     *
     * @param claimValue
     *         A claim value. May be null.
     *
     * @throws IllegalArgumentException
     *         The given salt and/or claim name are null.
     *
     * @since 1.1
     */
    public Disclosure(String salt, String claimName, int claimIndex, Object claimValue)
    {
        this(salt, claimName, claimIndex, claimValue, null, null);
    }


    /**
     * A private constructor for all the other constructors and
     * the implementation of the {@link #parse(String)} method.
     */
    private Disclosure(
            String salt, String claimName, int claimIndex,
            Object claimValue, String json, String disclosure)
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
            if (0 <= claimIndex)
            {
                // [ salt, [ claimName, claimIndex ], claimValue ]
                json = toJson(List.of(salt, List.of(claimName, claimIndex), claimValue));
            }
            else
            {
                // [ salt, claimName, claimValue ]
                json = toJson(List.of(salt, claimName, claimValue));
            }
        }

        // If a disclosure is not given.
        if (disclosure == null)
        {
            // Convert the JSON to UTF-8 bytes, then base64url-encode the bytes.
            disclosure = toBase64url(toUTF8Bytes(json));
        }

        this.salt          = salt;
        this.claimName     = claimName;
        this.claimIndex    = claimIndex;
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
     * Get the claim index.
     *
     * <p>
     * When this disclosure represents an array element, this method returns 0
     * or a positive integer. Otherwise, this method returns a negative integer.
     * </p>
     *
     * @return
     *         The claim index.
     *
     * @since 1.1
     */
    public int getClaimIndex()
    {
        return claimIndex;
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
     *         (5) The first element of the JSON array is not a JSON string.
     *         (6) The second element of the JSON array is neither a JSON string
     *             nor a JSON array.
     *         (7) When the second element is a JSON array, (a) its size is not
     *             2, (b) its first element is not a string, (c) its second
     *             element is not a number.
     *         (8) The claim name is a key reserved by the SD-JWT specification.
     */
    public static Disclosure parse(String disclosure)
    {
        if (disclosure == null)
        {
            return null;
        }

        // Base64url-decode the input to bytes, then build a string from the bytes.
        String json = fromUTF8Bytes(fromBase64url(disclosure));

        // Parse the string as a JSON array having 3 elements.
        List<?> elements = parseAsDisclosureElements(json);

        // Parse the first element as a salt.
        String salt = parseAsSalt(elements.get(0));

        // The third element is a claim value. It may be null.
        Object claimValue = elements.get(2);

        // The second element is either a string or an array having 2 elements.
        Object second = elements.get(1);

        String claimName;
        int    claimIndex;

        // In the former case, the string represents a claim name.
        if (second instanceof String)
        {
            claimName  = (String)second;
            claimIndex = -1;
        }
        // In the latter case, the first element of the array represents
        // an array name and the second element represents an array index.
        else if (second instanceof List)
        {
            List<?> list = parseAsNameAndIndex((List<?>)second);
            claimName  = (String)list.get(0);
            claimIndex = (int)   list.get(1);
        }
        else
        {
            throw new IllegalArgumentException(
                    "The second element is neither a string nor an array.");
        }

        // If the claim name is a reserved key.
        if (isReservedKey(claimName))
        {
            throw new IllegalArgumentException(
                    String.format("The claim name ('%s') is a reserved key.", claimName));
        }

        return new Disclosure(salt, claimName, claimIndex, claimValue, json, disclosure);
    }


    private static List<?> parseAsDisclosureElements(String json)
    {
        // Parse the string as a JSON array.
        List<?> elements = fromJson(json, List.class);

        if (elements == null || elements.size() != 3)
        {
            throw new IllegalArgumentException("Not a JSON array having 3 elements.");
        }

        return elements;
    }


    private static String parseAsSalt(Object element)
    {
        if (!(element instanceof String))
        {
            throw new IllegalArgumentException("The first element (salt) is not a string.");
        }

        return (String)element;
    }


    private static List<?> parseAsNameAndIndex(List<?> list)
    {
        if (list.size() != 2)
        {
            throw new IllegalArgumentException(
                    "The second element is an array but its size is not 2.");
        }

        Object first = list.get(0);
        if (!(first instanceof String))
        {
            throw new IllegalArgumentException(
                    "The first element in the array (claimName) is not a string.");
        }

        Object second = list.get(1);
        if (!(second instanceof Number))
        {
            throw new IllegalArgumentException(
                    "The second element in the array (claimIndex) is not a number.");
        }

        return List.of((String)first, ((Number)second).intValue());
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
