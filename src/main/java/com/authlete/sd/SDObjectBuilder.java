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
import static com.authlete.sd.SDConstants.KEY_SD;
import static com.authlete.sd.SDConstants.KEY_SD_ALG;
import static com.authlete.sd.SDUtility.isReservedKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * A utility to create a {@link Map} instance that represents a JSON object
 * which may contain the "{@code _sd}" array and the "{@code _sd_alg}" claim.
 *
 * <p>
 * <b>Example:</b>
 * </p>
 *
 * <blockquote>
 * <pre style="border:1px solid black; padding:1em;">
 * Disclosure disclosure = Disclosure.parse(
 *     <span style="color:brown;">"WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"</span>);
 *
 * <span style="color:darkgreen;">// Create an SDObjectBuilder instance with the default
 * // hash algorithm "sha-256".</span>
 * SDObjectBuilder builder = new SDObjectBuilder();
 *
 * <span style="color:darkgreen;">// Add the digest of the disclosure.</span>
 * builder.putSDClaim(disclosure);
 *
 * <span style="color:darkgreen;">// Add an arbitrary claim.</span>
 * String claimName  = <span style="color:brown;">"my_claim_name"</span>;
 * String claimValue = <span style="color:brown;">"my_claim_value"</span>;
 * builder.putClaim(claimName, claimValue);
 *
 * <span style="color:darkgreen;">// Build a map that represents a JSON object.</span>
 * Map<String, Object> map = builder.build(true);
 *
 * <span style="color:darkgreen;">// map ->
 * // {
 * //   "my_claim_name": "my_claim_value",
 * //   "_sd": [
 * //     "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY"
 * //   ],
 * //   "_sd_alg": "sha-256"
 * // }</span>
 * </pre>
 * </blockquote>
 *
 * @since 1.0
 */
public class SDObjectBuilder
{
    private final String hashAlgorithm;
    private final Map<String, Object> claims;
    private final DigestListBuilder digestListBuilder;


    /**
     * Constructor with the default hash algorithm ("{@code sha-256}").
     *
     * <p>
     * The hash algorithm is used when computing digest values that are to be
     * listed in the "{@code _sd}" array.
     * </p>
     */
    public SDObjectBuilder()
    {
        this(DEFAULT_HASH_ALGORITHM);
    }


    /**
     * Constructor with the specified hash algorithm.
     *
     * <p>
     * The hash algorithm is used when computing digest values that are to be
     * listed in the "{@code _sd}" array.
     * </p>
     *
     * @param hashAlgorithm
     *         A hash algorithm. If {@code null} is given, the default hash
     *         algorithm ("{@code sha-256}") is used.
     */
    public SDObjectBuilder(String hashAlgorithm)
    {
        this.hashAlgorithm = (hashAlgorithm != null)
                ? hashAlgorithm : DEFAULT_HASH_ALGORITHM;

        this.claims            = new LinkedHashMap<>();
        this.digestListBuilder = new DigestListBuilder(this.hashAlgorithm);
    }


    /**
     * Get the hash algorithm that has been specified by the constructor.
     *
     * <p>
     * The hash algorithm is used when computing digest values that are to be
     * listed in the "{@code _sd}" array.
     * </p>
     *
     * @return
     *         The hash algorithm.
     */
    public String getHashAlgorithm()
    {
        return hashAlgorithm;
    }


    /**
     * Put a normal claim.
     *
     * @param claimName
     *         A claim name. Must not be null.
     *
     * @param claimValue
     *         A claim value. May be null.
     *
     * @throws IllegalArgumentException
     *         The given claim name is null or a key reserved by the SD-JWT
     *         specification.
     */
    public void putClaim(String claimName, Object claimValue)
    {
        // If a claim name is not given.
        if (claimName == null)
        {
            throw new IllegalArgumentException("'claimName' is missing.");
        }

        // If the given claim name is a reserved key.
        if (isReservedKey(claimName))
        {
            throw new IllegalArgumentException(
                    String.format("The claim name ('%s') is a reserved key.", claimName));
        }

        // If any, remove the digest that corresponds to a disclosure
        // whose claim name is equal to the one given to this method.
        digestListBuilder.removeDigestByClaimName(claimName);

        // Put the claim as a normal one.
        claims.put(claimName, claimValue);
    }


    /**
     * Put the digest value of a selectively-disclosable claim.
     *
     * <p>
     * The digest of the given disclosure will appear in the "{@code _sd}" array.
     * </p>
     *
     * @param disclosure
     *         The disclosure of the claim.
     *
     * @return
     *         The {@link Disclosure} instance given to this method.
     *
     * @throws IllegalArgumentException
     *         The given disclosure is null.
     */
    public Disclosure putSDClaim(Disclosure disclosure)
    {
        // If a disclosure is not given.
        if (disclosure == null)
        {
            throw new IllegalArgumentException("'disclosure' is missing.");
        }

        // Add the digest of the disclosure.
        digestListBuilder.addDisclosureDigest(disclosure);

        // Remove the claim if it has been registered as a normal claim.
        claims.remove(disclosure.getClaimName());

        return disclosure;
    }


    /**
     * Put the digest value of a selectively-disclosable claim.
     *
     * <p>
     * This method is an alias of {@link #putSDClaim(Disclosure)
     * putSDClaim}{@code (new }{@link Disclosure#Disclosure(String, Object)
     * Disclosure}{@code (claimName, claimValue))}.
     * </p>
     *
     * @param claimName
     *         A claim name. Must not be null.
     *
     * @param claimValue
     *         A claim value. May be null.
     *
     * @return
     *         A {@link Disclosure} instance that was created for the
     *         specified claim.
     *
     * @throws IllegalArgumentException
     *         The given claim name is null.
     */
    public Disclosure putSDClaim(String claimName, Object claimValue)
    {
        return putSDClaim(new Disclosure(claimName, claimValue));
    }


    /**
     * Put the digest value of a selectively-disclosable claim.
     *
     * <p>
     * This method is an alias of {@link #putSDClaim(Disclosure)
     * putSDClaim}{@code (new }{@link Disclosure#Disclosure(String, String, Object)
     * Disclosure}{@code (salt, claimName, claimValue))}.
     * </p>
     *
     * @param salt
     *         A salt. Must not be null.
     *
     * @param claimName
     *         A claim name. Must not be null.
     *
     * @param claimValue
     *         A claim value. May be null.
     *
     * @return
     *         A {@link Disclosure} instance that was created for the
     *         specified claim.
     *
     * @throws IllegalArgumentException
     *         The given salt and/or claim name are null.
     */
    public Disclosure putSDClaim(String salt, String claimName, Object claimValue)
    {
        return putSDClaim(new Disclosure(salt, claimName, claimValue));
    }


    /**
     * Put the digest value of a selectively-disclosable claim.
     *
     * <p>
     * This method is an alias of {@link #putSDClaim(Disclosure)
     * putSDClaim}{@code (new }{@link Disclosure#Disclosure(String, int, Object)
     * Disclosure}{@code (claimName, claimIndex, claimValue))}.
     * </p>
     *
     * @param claimName
     *         A claim name (an array name). Must not be null.
     *
     * @param claimIndex
     *         A claim index (an array index).
     *
     * @param claimValue
     *         A claim value. May be null.
     *
     * @return
     *         A {@link Disclosure} instance that was created for the
     *         specified claim.
     *
     * @throws IllegalArgumentException
     *         The given claim name is null.
     *
     * @since 1.1
     */
    public Disclosure putSDClaim(String claimName, int claimIndex, Object claimValue)
    {
        return putSDClaim(new Disclosure(claimName, claimIndex, claimValue));
    }


    /**
     * Put the digest value of a selectively-disclosable claim.
     *
     * <p>
     * This method is an alias of {@link #putSDClaim(Disclosure)
     * putSDClaim}{@code (new }{@link Disclosure#Disclosure(String, String, int, Object)
     * Disclosure}{@code (salt, claimName, claimIndex, claimValue))}.
     * </p>
     *
     * @param salt
     *         A salt. Must not be null.
     *
     * @param claimName
     *         A claim name (an array name). Must not be null.
     *
     * @param claimIndex
     *         A claim index (an array index).
     *
     * @param claimValue
     *         A claim value. May be null.
     *
     * @return
     *         A {@link Disclosure} instance that was created for the
     *         specified claim.
     *
     * @throws IllegalArgumentException
     *         The given salt and/or claim name are null.
     *
     * @since 1.1
     */
    public Disclosure putSDClaim(String salt, String claimName, int claimIndex, Object claimValue)
    {
        return putSDClaim(new Disclosure(salt, claimName, claimIndex, claimValue));
    }


    /**
     * Put a decoy digest value, which will appear in the "{@code _sd}" array.
     *
     * @return
     *         The base64url-encoded digest value of a randomly-generated
     *         value computed with the hash algorithm.
     */
    public String putDecoyDigest()
    {
        return digestListBuilder.addDecoyDigest();
    }


    /**
     * Put decoy digest values, which will appear in the "{@code _sd}" array.
     *
     * @param count
     *         The number of decoy digest values to add.
     *
     * @return
     *         A list of base64url-encoded digest values of randomly-generated
     *         values computed with the hash algorithm.
     */
    public List<String> putDecoyDigests(int count)
    {
        return digestListBuilder.addDecoyDigests(count);
    }


    /**
     * Create a {@link Map} instance that represents a JSON object which may
     * include the "{@code _sd}" array.
     *
     * <p>
     * This method is an alias of {@link #build(boolean) build}{@code (false)}.
     * </p>
     *
     * @return
     *         A {@link Map} instance that represents a JSON object.
     */
    public Map<String, Object> build()
    {
        return build(/*hashAlgorithmIncluded*/false);
    }


    /**
     * Create a {@link Map} instance that represents a JSON object which may
     * include the "{@code _sd}" array and the "{@code _sd_alg}" claim.
     *
     * <p>
     * The "{@code _sd}" array will not appear in the created map if no digest
     * value has been put to this builder. In other words, if none of the
     * {@code putSDClaim} method variants, the {@code putDecoyDigest()} method
     * and the {@code putDecoyDigests(int}) method have been called, the
     * "{@code _sd}" array will not appear.
     * </p>
     *
     * @param hashAlgorithmIncluded
     *          {@code true} to include the "{@code _sd_alg}" claim in the
     *          created map.
     *
     * @return
     *         A {@link Map} instance that represents a JSON object.
     */
    public Map<String, Object> build(boolean hashAlgorithmIncluded)
    {
        Map<String, Object> output = new LinkedHashMap<>();

        output.putAll(claims);

        List<String> digestList = digestListBuilder.build();

        // From the SD-JWT specification:
        //
        //   The array MAY be empty in case the Issuer decided not to
        //   selectively disclose any of the claims at that level.
        //   However, it is RECOMMENDED to omit _sd claim in this case
        //   to save space.
        //
        if (digestList.size() != 0)
        {
            // Put the "_sd" array that lists digest values.
            output.put(KEY_SD, digestList);
        }

        if (hashAlgorithmIncluded)
        {
            // Put the "_sd_alg" claim that holds the name of the
            // hash algorithm.
            output.put(KEY_SD_ALG, getHashAlgorithm());
        }

        return output;
    }
}
