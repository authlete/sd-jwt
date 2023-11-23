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
import static com.authlete.sd.SDConstants.RETAINED_CLAIMS;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;


/**
 * A utility to make elements in a map or a list selectively-disclosable
 * recursively.
 *
 * <p>
 * Decoy digests are automatically added unless decoy magnification ratio
 * is set to 0.0 through constructors or the {@link #setDecoyMagnification(double, double)}
 * method.
 * </p>
 *
 * <p>
 * Some claims such as "{@code iss}" and "{@code iat}" are retained without
 * being made selectively-disclosable. See the description of the {@link
 * #getRetainedClaims()} method for details.
 * </p>
 *
 * <blockquote>
 * <pre style="border:1px solid black; padding:1em;">
 * <span style="color:darkgreen;">// <b>Original dataset</b>
 * //
 * //   {
 * //     <span style="color:navy">"key-1"</span>: <span style="color:purple">"value-1"</span>,
 * //     <span style="color:navy">"key-2"</span>: [
 * //       <span style="color:purple">"element-1"</span>,
 * //       <span style="color:purple">"element-2"</span>
 * //     ],
 * //     <span style="color:navy">"key-3"</span>: {
 * //       <span style="color:navy">"sub-key-1"</span>: <span style="color:purple">"sub-value-1"</span>,
 * //       <span style="color:navy">"sub-key-2"</span>: <span style="color:purple">"sub-value-2"</span>,
 * //     },
 * //   }
 * //
 * </span>
 * List&lt;String&gt; sublist = List.of(
 *         <span style="color:brown;">"element-1"</span>,
 *         <span style="color:brown;">"element-2"</span>
 * );
 *
 * Map&lt;String, String&gt; submap = Map.of(
 *         <span style="color:brown;">"sub-key-1"</span>, <span style="color:brown;">"sub-value-1"</span>,
 *         <span style="color:brown;">"sub-key-2"</span>, <span style="color:brown;">"sub-value-2"</span>
 * );
 *
 * Map&lt;String, Object&gt; originalMap = Map.of(
 *         <span style="color:brown;">"key-1"</span>, <span style="color:brown;">"value-1"</span>,
 *         <span style="color:brown;">"key-2"</span>, sublist,
 *         <span style="color:brown;">"key-3"</span>, submap
 * );
 *
 * <span style="color:darkgreen;">// Encoder</span>
 * SDObjectEncoder encoder = new SDObjectEncoder();
 *
 * <span style="color:darkgreen;">// Encode</span>
 * Map&lt;String, Object&gt; encodedMap = encoder.encode(originalMap);
 *
 * <span style="color:darkgreen;">// Disclosures yielded as a result of the encoding process.</span>
 * List&lt;Disclosure&gt; disclosures = encoder.getDisclosures();
 *
 * <span style="color:darkgreen;">// <b>Encoded dataset</b>
 * //
 * //   {
 * //     <span style="color:navy">"key-2"</span>: [
 * //       { <span style="color:navy">"..."</span>: <span style="color:purple">"Z_JV6E3FColTFBqUrvfa366V27BFy8cf8fa59NQdavg"</span> },
 * //       { <span style="color:navy">"..."</span>: <span style="color:purple">"p-vA6nPBgbL-Zgzd5MkVV7RrFPvMCV_f0N9p3CKOLVo"</span> },
 * //       { <span style="color:navy">"..."</span>: <span style="color:purple">"NVpowlkRQq9aC8aJAS3tz7Gzs3PolUJ7bZLYZiUg5pw"</span> },
 * //       { <span style="color:navy">"..."</span>: <span style="color:purple">"TfdBAy9CRDAhoyB2O3tcGUWOKnfSzQ1wKDTwJQyuFVU"</span> },
 * //       { <span style="color:navy">"..."</span>: <span style="color:purple">"Ujg9QqkNQ0tKN_DiPoCQOmHAWGThokrjA5ceve6Xxik"</span> }
 * //     ],
 * //     <span style="color:navy">"key-3"</span>: {
 * //       <span style="color:navy">"_sd"</span>: [
 * //         <span style="color:purple">"JVWbh08VUtBXLWOH16OgPMFZu7qGmKIc7Gt0dxwJin0"</span>,
 * //         <span style="color:purple">"YJ_T7R1qZsfdDIKoHFQ1ubOToI-DHZHBvZwBU6S1svE"</span>,
 * //         <span style="color:purple">"Z14X_kICU8SpDGpfDQ2mP1LfWAMtdPPRPJ_434cdKe4"</span>,
 * //         <span style="color:purple">"r67vz8Rq22eoCw_D-xDVa1bRucngVuRAExSQvWdbrXo"</span>
 * //       ]
 * //     },
 * //     <span style="color:navy">"_sd"</span>: [
 * //       <span style="color:purple">"--3D5V1QiCzfs7gt4hxlaiFh02bBcUKH6VKCxAcPuGk"</span>,
 * //       <span style="color:purple">"ON2rSnqtfmLcJTrKKP5_l6swD3AkMbcmjb80hge2eMs"</span>,
 * //       <span style="color:purple">"wf2OtpIlIqG58GfXN6-jiDX-k1Wt4eJX-nPWbTdfonM"</span>
 * //     ],
 * //     <span style="color:navy">"_sd_alg"</span>: <span style="color:purple">"sha-256"</span>
 * //   }
 * //
 * // <b>Disclosures</b>
 * //
 * //   | digest                                      | claim name | claim value  |
 * //   |---------------------------------------------|------------|--------------|
 * //   | ON2rSnqtfmLcJTrKKP5_l6swD3AkMbcmjb80hge2eMs | key-1      | value-1      |
 * //   | NVpowlkRQq9aC8aJAS3tz7Gzs3PolUJ7bZLYZiUg5pw | (null)     | element-1    |
 * //   | TfdBAy9CRDAhoyB2O3tcGUWOKnfSzQ1wKDTwJQyuFVU | (null)     | element-2    |
 * //   | r67vz8Rq22eoCw_D-xDVa1bRucngVuRAExSQvWdbrXo | sub-key-1  | sub-value-1  |
 * //   | Z14X_kICU8SpDGpfDQ2mP1LfWAMtdPPRPJ_434cdKe4 | sub-key-2  | sub-value-2  |
 * //</span>
 * </pre>
 * </blockquote>
 *
 * @since 1.3
 */
public class SDObjectEncoder
{
    private static final double DECOY_MAGNIFICATION_MIN_LIMIT   =  0.0;
    private static final double DECOY_MAGNIFICATION_MAX_LIMIT   = 10.0;
    private static final double DECOY_MAGNIFICATION_MIN_DEFAULT =  0.5;
    private static final double DECOY_MAGNIFICATION_MAX_DEFAULT =  1.5;


    private final Random random = new SecureRandom();
    private String hashAlgorithm;
    private double decoyMagnificationMin;
    private double decoyMagnificationMax;
    private boolean hashAlgorithmIncluded;
    private final Set<String> retainedClaims;
    private List<Disclosure> disclosures;


    /**
     * The default constructor with the default hash algorithm
     * ("{@code sha-256}") and the default decoy magnification ratio
     * (min = 0&#x2E;5, max = 1&#x2E;5).
     */
    public SDObjectEncoder()
    {
        this(DEFAULT_HASH_ALGORITHM, DECOY_MAGNIFICATION_MIN_DEFAULT, DECOY_MAGNIFICATION_MAX_DEFAULT);
    }


    /**
     * A constructor with the specified hash algorithm and the default decoy
     * magnification ratio (min = 0&#x2E;5, max = 1&#x2E;5).
     *
     * @param hashAlgorithm
     *         The hash algorithm for digests. If {@code null} is given, the
     *         default hash algorithm ("{@code sha-256}") is used.
     */
    public SDObjectEncoder(String hashAlgorithm)
    {
        this(hashAlgorithm, DECOY_MAGNIFICATION_MIN_DEFAULT, DECOY_MAGNIFICATION_MAX_DEFAULT);
    }


    /**
     * A constructor with the default hash algorithm ("{@code sha-256}") and
     * the specified decoy magnification ratio.
     *
     * <p>
     * The pair of the decoy magnification arguments specifies the range of decoy
     * magnification ratio. The actual ratio is determined randomly between the
     * range for each JSON object and JSON array. The number of inserted decoys is
     * computed by multiplying the ratio to the size of the original JSON object
     * or the length of the original JSON array.
     * </p>
     *
     * <p>
     * If 0.0 is set to both the decoy magnification arguments, no decoy is inserted.
     * </p>
     *
     * <pre>
     * <span style="color:darkgreen;">// Create an encoder that yields no decoy digests.</span>
     * SDObjectEncoder encoder = new SDObjectEncoder(0.0, 0.0);
     * </pre>
     *
     * @param decoyMagnificationMin
     *         The minimum decoy magnification ratio. If a negative value is
     *         given, 0.0 is used instead. If a value greater than 10.0 is
     *         given, 10.0 is used instead.
     *
     * @param decoyMagnificationMax
     *         The maximum decoy magnification ratio. If a negative value is
     *         given, 0.0 is used instead. If a value greater than 10.0 is
     *         given, 10.0 is used instead.
     */
    public SDObjectEncoder(double decoyMagnificationMin, double decoyMagnificationMax)
    {
        this(DEFAULT_HASH_ALGORITHM, decoyMagnificationMin, decoyMagnificationMax);
    }


    /**
     * A constructor with the specified hash algorithm and decoy magnification ratio.
     *
     * <p>
     * The pair of the decoy magnification arguments specifies the range of decoy
     * magnification ratio. The actual ratio is determined randomly between the
     * range for each JSON object and JSON array. The number of inserted decoys is
     * computed by multiplying the ratio to the size of the original JSON object
     * or the length of the original JSON array.
     * </p>
     *
     * <p>
     * If 0.0 is set to both the decoy magnification arguments, no decoy is inserted.
     * </p>
     *
     * <pre>
     * <span style="color:darkgreen;">// Create an encoder that yields no decoy digests.</span>
     * SDObjectEncoder encoder = new SDObjectEncoder(null, 0.0, 0.0);
     * </pre>
     *
     * @param hashAlgorithm
     *         The hash algorithm for digests. If {@code null} is given, the
     *         default hash algorithm ("{@code sha-256}") is used.
     *
     * @param decoyMagnificationMin
     *         The minimum decoy magnification ratio. If a negative value is
     *         given, 0.0 is used instead. If a value greater than 10.0 is
     *         given, 10.0 is used instead.
     *
     * @param decoyMagnificationMax
     *         The maximum decoy magnification ratio. If a negative value is
     *         given, 0.0 is used instead. If a value greater than 10.0 is
     *         given, 10.0 is used instead.
     */
    public SDObjectEncoder(String hashAlgorithm, double decoyMagnificationMin, double decoyMagnificationMax)
    {
        if (decoyMagnificationMin > decoyMagnificationMax)
        {
            throw new IllegalArgumentException("decoyMagnificationMin > decoyMagnificationMax");
        }

        this.hashAlgorithm         = normalizeHashAlgorithm(hashAlgorithm);
        this.decoyMagnificationMin = normalizeDecoyMagnification(decoyMagnificationMin);
        this.decoyMagnificationMax = normalizeDecoyMagnification(decoyMagnificationMax);
        this.hashAlgorithmIncluded = true;
        this.retainedClaims        = new TreeSet<>(RETAINED_CLAIMS);
    }


    private static String normalizeHashAlgorithm(String hashAlgorithm)
    {
        return (hashAlgorithm != null) ? hashAlgorithm : DEFAULT_HASH_ALGORITHM;
    }


    private static double normalizeDecoyMagnification(double magnification)
    {
        return between(DECOY_MAGNIFICATION_MIN_LIMIT, magnification,
                       DECOY_MAGNIFICATION_MAX_LIMIT);
    }


    private static double between(double min, double value, double max)
    {
        return Math.max(min, Math.min(value, max));
    }


    /**
     * Get the hash algorithm for digests.
     *
     * @return
     *         The hash algorithm.
     */
    public String getHashAlgorithm()
    {
        return hashAlgorithm;
    }


    /**
     * Set the hash algorithm for digests.
     *
     * @param hashAlgorithm
     *         The hash algorithm. If {@code null} is given, the default hash
     *         algorithm ("{@code sha-256}") is used.
     *
     * @return
     *         {@code this} object.
     */
    public SDObjectEncoder setHashAlgorithm(String hashAlgorithm)
    {
        this.hashAlgorithm = normalizeHashAlgorithm(hashAlgorithm);

        return this;
    }


    /**
     * Set the decoy magnification ratio.
     *
     * <p>
     * The pair of the arguments specifies the range of decoy magnification
     * ratio. The actual ratio is determined randomly between the range for
     * each JSON object and SON array. The number of inserted decoys is
     * computed by multiplying the ratio to the size of the original JSON
     * object or the length of the original JSON array.
     * </p>
     *
     * <p>
     * If 0.0 is set to both the arguments, no decoy is inserted.
     * </p>
     *
     * <pre>
     * <span style="color:darkgreen;">// Yield no decoy digests.</span>
     * encoder.{@link #setDecoyMagnification(double, double) setDecoyMagnification}(0.0, 0.0);
     * </pre>
     *
     * @param min
     *         The minimum decoy magnification ratio. If a negative value is
     *         given, 0.0 is used instead. If a value greater than 10.0 is
     *         given, 10.0 is used instead.
     *
     * @param max
     *         The maximum decoy magnification ratio. If a negative value is
     *         given, 0.0 is used instead. If a value greater than 10.0 is
     *         given, 10.0 is used instead.
     *
     * @return
     *         {@code this} object.
     */
    public SDObjectEncoder setDecoyMagnification(double min, double max)
    {
        if (min > max)
        {
            throw new IllegalArgumentException("min > max");
        }

        this.decoyMagnificationMin = normalizeDecoyMagnification(min);
        this.decoyMagnificationMax = normalizeDecoyMagnification(max);

        return this;
    }


    /**
     * Get the flag indicating whether the "{@code _sd_alg}" key (that denotes
     * the hash algorithm for digests) will be included in the encoded map.
     *
     * @return
     *         {@code true} if the "{@code _sd_alg}" key will be included in
     *         the encoded map.
     */
    public boolean isHashAlgorithmIncluded()
    {
        return hashAlgorithmIncluded;
    }


    /**
     * Set the flag indicating whether the "{@code _sd_alg}" key (that denotes
     * the hash algorithm for digests) will be included in the encoded map.
     *
     * @param included
     *         {@code true} to include the "{@code _sd_alg}" key in the encoded
     *         map. {@code false} not to include the key.
     *
     * @return
     *         {@code this} object.
     */
    public SDObjectEncoder setHashAlgorithmIncluded(boolean included)
    {
        this.hashAlgorithmIncluded = included;

        return this;
    }


    /**
     * Get the set of claims that are retained without being made
     * selectively-disclosable when they appear in the top-level map.
     *
     * <p>
     * By default, the following claims are registered as ones to retain.
     * </p>
     *
     * <ul>
     *   <li>{@code iss}
     *   <li>{@code iat}
     *   <li>{@code nbf}
     *   <li>{@code exp}
     *   <li>{@code cnf}
     *   <li>{@code vct}
     *   <li>{@code status}
     * </ul>
     *
     * <p>
     * By modifying the {@code Set} object returned from this method, the
     * behavior of this encoder can be changed. For instance, the example
     * below makes the encoder retain the "{@code sub}" claim.
     * </p>
     *
     * <pre>
     * encoder.{@link #getRetainedClaims()}.add(<span style="color:brown;">"sub"</span>);
     * </pre>
     *
     * @return
     *         The set of claims to retain.
     */
    public Set<String> getRetainedClaims()
    {
        return retainedClaims;
    }


    /**
     * Get the list of {@link Disclosure}s yielded as a result of the encoding
     * process.
     *
     * <p>
     * On every call of either the {@link #encode(Map)} method or the
     * {@link #encode(List)} method, the disclosure list is reset. The "reset"
     * here means that a new {@code List} instance is created and assigned,
     * and the previous one (if any) is detached.
     * </p>
     *
     * @return
     *         The list of {@link Disclosure}s.
     */
    public List<Disclosure> getDisclosures()
    {
        return disclosures;
    }


    /**
     * Encode the content of the given map.
     *
     * <p>
     * On the entry of this method, the disclosure list returned from the
     * {@link #getDisclosures()} method is reset. The "reset" here means that
     * a new {@code List} instance is created and assigned, and the previous
     * one (if any) is detached.
     * </p>
     *
     * <p>
     * Some claims such as "{@code iss}" and "{@code iat}" are retained without
     * being made selectively-disclosable when they appear in the top-level map.
     * See the description of the {@link #getRetainedClaims()} method for details.
     * </p>
     *
     * <p>
     * The encoded map will contain the "{@code _sd_alg}" key that denotes the
     * hash algorithm for digests. If the key should not be included, call
     * {@link #setHashAlgorithmIncluded(boolean) setHashAlgorithmIncluded}{@code
     * (false)} before calling this method.
     * </p>
     *
     * @param input
     *         The input map. If {@code null} is given, {@code null} is returned.
     *
     * @return
     *         The encoded map.
     */
    public Map<String, Object> encode(Map<String, Object> input)
    {
        reset();

        if (input == null)
        {
            return null;
        }

        // Encode the given map.
        return encodeMap(input, /* top */ true);
    }


    /**
     * Encode the content of the given list.
     *
     * <p>
     * On the entry of this method, the disclosure list returned from the
     * {@link #getDisclosures()} method is reset. The "reset" here means that
     * a new {@code List} instance is created and assigned, and the previous
     * one (if any) is detached.
     * </p>
     *
     * @param input
     *         The input list. If {@code null} is given, {@code null} is returned.
     *
     * @return
     *         The encoded list.
     */
    public List<Object> encode(List<?> input)
    {
        reset();

        if (input == null)
        {
            return null;
        }

        // Encode the given list.
        return encodeList(input);
    }


    private void reset()
    {
        // Reset the list of disclosures.
        disclosures = new ArrayList<>();
    }


    private Map<String, Object> encodeMap(Map<String, Object> input)
    {
        return encodeMap(input, /* top */ false);
    }


    @SuppressWarnings("unchecked")
    private Map<String, Object> encodeMap(Map<String, Object> input, boolean top)
    {
        SDObjectBuilder builder = new SDObjectBuilder(getHashAlgorithm());

        // For each key-value pair in the input map.
        for (Map.Entry<String, Object> entry : input.entrySet())
        {
            String key   = entry.getKey();
            Object value = entry.getValue();

            // If the input map is the top-level map and the key is a
            // claim to retain.
            if (top && retainedClaims.contains(key))
            {
                // Add the claim without making it selectively-disclosable.
                builder.putClaim(key, value);
            }
            else if (value instanceof Map)
            {
                // Encode the sub map.
                value = encodeMap((Map<String, Object>)value);
                builder.putClaim(key, value);
            }
            else if (value instanceof List)
            {
                // Encode the list.
                value = encodeList((List<?>)value);
                builder.putClaim(key, value);
            }
            else
            {
                // Key-value pairs of other types are made selectively-
                // disclosable here and the digests of their disclosures
                // are added to the "_sd" array in the JSON object here.
                Disclosure disclosure = builder.putSDClaim(key, value);
                disclosures.add(disclosure);
            }
        }

        // Compute the number of decoys to insert.
        int decoyCount = computeDecoyCount(input.size());

        // Insert decoys.
        builder.putDecoyDigests(decoyCount);

        // Build an encoded map that may contain the "_sd" array.
        return builder.build(top && hashAlgorithmIncluded);
    }


    @SuppressWarnings("unchecked")
    private List<Object> encodeList(List<?> input)
    {
        // The size of the input list.
        int inputSize = input.size();

        // Compute the number of decoys based on the size of the input list.
        int decoyCount = computeDecoyCount(inputSize);

        // The encoded list.
        List<Object> encodedList = new ArrayList<>(inputSize + decoyCount);

        // For each element in the input list.
        for (Object value : input)
        {
            if (value instanceof Map)
            {
                // Encode the sub map.
                value = encodeMap((Map<String, Object>)value);
            }
            else if (value instanceof List)
            {
                // Encode the sub list.
                value = encodeList((List<?>)value);
            }
            else
            {
                // Elements of other types are made selectively-disclosable here.
                Disclosure disclosure = new Disclosure(value);
                disclosures.add(disclosure);

                // value = { "...": "<digest>" }
                value = disclosure.toArrayElement(getHashAlgorithm());
            }

            encodedList.add(value);
        }

        // Repeat as many times as the number of decoys.
        for (int i = 0; i < decoyCount; i++)
        {
            // Compute the index at which a decoy is inserted.
            int bound = encodedList.size() + 1;
            int index = random.nextInt(bound);

            // Insert a decoy element at the randomly-selected position.
            encodedList.add(index, generateDecoyArrayElement());
        }

        // The encoded list.
        return encodedList;
    }


    private int computeDecoyCount(int baseCount)
    {
        double min = decoyMagnificationMin;
        double max = decoyMagnificationMax;
        double d;

        if (min == max)
        {
            d = min;
        }
        else
        {
            // A random double value between the min and the max.
            d = random.doubles(1, min, max).findFirst().getAsDouble();
        }

        return (int)Math.round(baseCount * d);
    }


    private Map<String, Object> generateDecoyArrayElement()
    {
        // { "...": "<digest>" }
        return SDUtility.generateDecoyArrayElement(getHashAlgorithm());
    }
}
