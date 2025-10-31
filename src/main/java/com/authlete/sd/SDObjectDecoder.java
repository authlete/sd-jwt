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
import static com.authlete.sd.SDConstants.KEY_THREE_DOTS;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * A utility to decode selectively-disclosable elements in a map or a list
 * recursively.
 *
 * <blockquote>
 * <pre style="border:1px solid black; padding:1em;">
 * <span style="color:darkgreen;">// <b>Original dataset</b>
 * //
 * //   {
 * //     <span style="color:navy">"key-1"</span>: <span style="color:purple">"value-1"</span>,
 * //     <span style="color:navy">"key-2"</span>: <span style="color:purple">"value-2"</span>
 * //   }
 * //</span>
 * Map&lt;String, Object&gt; originalMap = Map.of(
 *         <span style="color:brown;">"key-1"</span>, <span style="color:brown;">"value-1"</span>,
 *         <span style="color:brown;">"key-2"</span>, <span style="color:brown;">"value-2"</span>
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
 * <span style="color:darkgreen;">// Disclosures for claims to disclose.</span>
 * List&lt;Disclosure&gt; disclosed = disclosures.stream()
 *         .filter(d -> <span style="color:brown;">"key-1"</span>.equals(d.getClaimName()))
 *         .collect(Collectors.toList());
 *
 * <span style="color:darkgreen;">// Decode the encoded map with the selected disclosures.</span>
 * SDObjectDecoder decoder = new SDObjectDecoder();
 * Map&lt;String, Object&gt; decodedMap = decoder.decode(encodedMap, disclosed);
 *
 * <span style="color:darkgreen;">// <b>Decoded dataset</b>
 * //
 * //   {
 * //     <span style="color:navy">"key-1"</span>: <span style="color:purple">"value-1"</span>
 * //   }
 * //</span>
 * </pre>
 * </blockquote>
 *
 * @since 1.3
 */
public class SDObjectDecoder
{
    /**
     * Decode the given map with the specified disclosures.
     *
     * @param encodedMap
     *         The input map. If {@code null} is given, {@code null} is returned.
     *
     * @param disclosures
     *         Disclosures for claims to disclose. If {@code null} is given, it
     *         means that none of selectively-disclosable elements in the input
     *         map are disclosed.
     *
     * @return
     *         The decoded map.
     */
    public Map<String, Object> decode(
            Map<String, Object> encodedMap, Collection<Disclosure> disclosures)
    {
        if (encodedMap == null)
        {
            return null;
        }

        // Determine the hash algorithm. It is the value specified by
        // the "_sd_alg" key in the encoded map, or the default algorithm
        // if the key is not found in the encoded map or its value is null.
        String hashAlgorithm = determineHashAlgorithm(encodedMap);

        // Create mappings from a disclosure digest to a disclosure.
        // The digest is computed using the hash algorithm.
        Map<String, Disclosure> digestMap =
                createDigestMap(hashAlgorithm, disclosures);

        // Decode the encoded map.
        return decodeMap(digestMap, encodedMap);
    }


    /**
     * Decode the given list with the specified disclosures and the default hash
     * algorithm ("{@code sha-256}").
     *
     * @param encodedList
     *         The input list. If {@code null} is given, {@code null} is returned.
     *
     * @param disclosures
     *         Disclosures for claims to disclose. If {@code null} is given, it
     *         means that none of selectively-disclosable elements in the input
     *         list are disclosed.
     *
     * @return
     *         The decoded list.
     */
    public List<Object> decode(
            List<?> encodedList, Collection<Disclosure> disclosures)
    {
        return decode(encodedList, disclosures, DEFAULT_HASH_ALGORITHM);
    }


    /**
     * Decode the given list with the specified disclosures and hash algorithm.
     *
     * @param encodedList
     *         The input list. If {@code null} is given, {@code null} is returned.
     *
     * @param disclosures
     *         Disclosures for claims to disclose. If {@code null} is given, it
     *         means that none of selectively-disclosable elements in the input
     *         list are disclosed.
     *
     * @param hashAlgorithm
     *         The hash algorithm for digests. If {@code null} is given, the
     *         default hash algorithm ("{@code sha-256}") is used.
     *
     * @return
     *         The decoded list.
     */
    public List<Object> decode(
            List<?> encodedList, Collection<Disclosure> disclosures, String hashAlgorithm)
    {
        if (encodedList == null)
        {
            return null;
        }

        if (hashAlgorithm == null)
        {
            // Use the default hash algorithm.
            hashAlgorithm = DEFAULT_HASH_ALGORITHM;
        }

        // Create mappings from a disclosure digest to a disclosure.
        // The digest is computed using the hash algorithm.
        Map<String, Disclosure> digestMap =
                createDigestMap(hashAlgorithm, disclosures);

        // Decode the encoded list.
        return decodeList(digestMap, encodedList);
    }


    private static String determineHashAlgorithm(Map<String, Object> encodedMap)
    {
        // If the map does not contain "_sd_alg".
        if (!encodedMap.containsKey(KEY_SD_ALG))
        {
            // Use the default hash algorithm.
            return DEFAULT_HASH_ALGORITHM;
        }

        // The value of "_sd_alg".
        Object alg = encodedMap.get(KEY_SD_ALG);

        // If the value of "_sd_alg" is not a string.
        if (!(alg instanceof String))
        {
            throw new IllegalArgumentException(
                    "The value of '_sd_alg' is not a string.");
        }

        // The hash algorithm specified by "_sd_alg".
        return (String)alg;
    }


    private static Map<String, Disclosure> createDigestMap(
            String hashAlgorithm, Collection<Disclosure> disclosures)
    {
        // Mappings from a disclosure digest to a disclosure.
        Map<String, Disclosure> map = new LinkedHashMap<>();

        if (disclosures == null)
        {
            // Return an empty map.
            return map;
        }

        // For each disclosure.
        for (Disclosure disclosure : disclosures)
        {
            if (disclosure == null)
            {
                // Ignore.
                continue;
            }

            // Compute the digest of the disclosure with the hash algorithm.
            // The digest is used as a key.
            String key = disclosure.digest(hashAlgorithm);

            // Add a mapping from the disclosure digest to the disclosure.
            map.put(key, disclosure);
        }

        // Mappings from a disclosure digest to a disclosure.
        return map;
    }


    private Map<String, Object> decodeMap(
            Map<String, Disclosure> digestMap, Map<String, Object> encodedMap)
    {
        // A map that holds decoded key-value pairs.
        Map<String, Object> decodedMap = new LinkedHashMap<>();

        // For each key-value pair in the encoded map.
        for (Map.Entry<String, Object> entry : encodedMap.entrySet())
        {
            String key   = entry.getKey();
            Object value = entry.getValue();

            // Decode the key-value pair.
            decodeMapEntry(digestMap, key, value, decodedMap);
        }

        // A map that holds decoded key-value pairs.
        return decodedMap;
    }


    @SuppressWarnings("unchecked")
    private void decodeMapEntry(
            Map<String, Disclosure> digestMap,
            String key, Object value, Map<String, Object> decodedMap)
    {
        // If the key is "_sd_alg".
        if (KEY_SD_ALG.equals(key))
        {
            // "_sd_alg" does not appear in the decoded map.
            return;
        }

        // If the key is "_sd".
        if (KEY_SD.equals(key))
        {
            // Process the "_sd" array.
            decodeSD(digestMap, value, decodedMap);
            return;
        }

        // If the value is a map.
        if (value instanceof Map)
        {
            // Decode the nested map.
            value = decodeMap(digestMap, (Map<String, Object>)value);
        }
        // If the value is a list.
        else if (value instanceof List)
        {
            // Decode the list.
            value = decodeList(digestMap, (List<?>)value);
        }

        // Add the decoded key-value pair.
        decodedMap.put(key, value);
    }


    private void decodeSD(
            Map<String, Disclosure> digestMap,
            Object sd, Map<String, Object> decodedMap)
    {
        // If the value of "_sd" is null.
        if (sd == null)
        {
            // Ignore.
            return;
        }

        // If the value of "_sd" is not a list.
        if (!(sd instanceof List))
        {
            throw new IllegalArgumentException(
                    "The value of '_sd' is not an array.");
        }

        // For each element in the "_sd" array.
        for (Object element : (List<?>)sd)
        {
            // If the element is null.
            if (element == null)
            {
                // Ignore.
                continue;
            }

            // If the element is not a string.
            if (!(element instanceof String))
            {
                throw new IllegalArgumentException(
                        "An element in the '_sd' array is not a string.");
            }

            // The value of the element should be the digest of a disclosure.
            String digest = (String)element;

            // Process the digest.
            decodeSDElement(digestMap, digest, decodedMap);
        }
    }


    @SuppressWarnings("unchecked")
    private void decodeSDElement(
            Map<String, Disclosure> digestMap,
            String digest, Map<String, Object> decodedMap)
    {
        // Get a disclosure that corresponds to the digest.
        Disclosure disclosure = digestMap.get(digest);

        // If the disclosure that corresponds to the digest is not found.
        if (disclosure == null)
        {
            // There are two possibilities.
            //
            //   1. The claim corresponding to the digest is not disclosed.
            //   2. The digest is a decoy digest.
            //
            // In either case, no key-value pair is added to the decoded map.
            return;
        }

        // The key-value pair that the disclosure holds.
        String claimName  = disclosure.getClaimName();
        Object claimValue = disclosure.getClaimValue();

        // If the claim name is null.
        if (claimName == null)
        {
            // That the claim name of a disclosure is null means that the
            // disclosure is for an array element, not for an object property.
            throw new IllegalArgumentException(
                    "The digest of a disclosure for an array element is found in the '_sd' array.");
        }

        // If the value is a map.
        if (claimValue instanceof Map)
        {
            // Decode the nested map.
            claimValue = decodeMap(digestMap, (Map<String, Object>)claimValue);
        }
        // If the value is a list.
        else if (claimValue instanceof List)
        {
            // Decode the list.
            claimValue = decodeList(digestMap, (List<?>)claimValue);
        }

        // Add the disclosed key-value pair.
        decodedMap.put(claimName, claimValue);
    }


    private List<Object> decodeList(
            Map<String, Disclosure> digestMap, List<?> encodedList)
    {
        // A list that holds decoded elements.
        List<Object> decodedList = new ArrayList<>();

        // For each element in the encoded list.
        for (Object element : encodedList)
        {
            // Process the element.
            decodeListElement(digestMap, element, decodedList);
        }

        // A list that holds decoded elements.
        return decodedList;
    }


    @SuppressWarnings("unchecked")
    private void decodeListElement(
            Map<String, Disclosure> digestMap,
            Object element, List<Object> decodedList)
    {
        if (element instanceof Map)
        {
            Map<String, Object> map = (Map<String, Object>)element;

            // If the map contains the key "..." (three dots).
            if (map.containsKey(KEY_THREE_DOTS))
            {
                // The map represents a selectively-disclosable array element.
                decodeListElementMap(digestMap, map, decodedList);
                return;
            }
            else
            {
                // Decode the encoded map.
                element = decodeMap(digestMap, map);
            }
        }
        else if (element instanceof List)
        {
            // Decode the encoded list.
            element = decodeList(digestMap, (List<?>)element);
        }

        // Add the element to the decoded list.
        decodedList.add(element);
    }


    private void decodeListElementMap(
            Map<String, Disclosure> digestMap,
            Map<String, Object> element, List<Object> decodedList)
    {
        // If the map contains other keys than "...".
        if (element.size() != 1)
        {
            throw new IllegalArgumentException(
                    "An object containing the three-dot key ('...') must not contain other keys.");
        }

        // The value of "...".
        Object dots = element.get(KEY_THREE_DOTS);

        // If the value of "..." is null.
        if (dots == null)
        {
            // Ignore.
            return;
        }

        // If the value of "..." is not a string.
        if (!(dots instanceof String))
        {
            throw new IllegalArgumentException(
                    "The value of the three-dot key ('...') is not a string.");
        }

        // The value of '...' should be the digest of a disclosure.
        String digest = (String)dots;

        // Process the digest.
        decodeDots(digestMap, digest, decodedList);
    }


    private void decodeDots(
            Map<String, Disclosure> digestMap,
            String digest, List<Object> decodedList)
    {
        // Get a disclosure that corresponds to the digest.
        Disclosure disclosure = digestMap.get(digest);

        // If the disclosure that corresponds to the digest is not found.
        if (disclosure == null)
        {
            // There are two possibilities.
            //
            //   1. The array element corresponding to the digest is not disclosed.
            //   2. The digest is a decoy digest.
            //
            // In either case, no element is added to the decoded list.
            return;
        }

        // If the disclosure has a claim name.
        if (disclosure.getClaimName() != null)
        {
            // That the claim name of a disclosure is not null means that the
            // disclosure is for an object property, not for an array element.
            throw new IllegalArgumentException(
                    "The digest of a disclosure for an object property is specified by '...'.");
        }

        // Add the disclosed array element.
        decodedList.add(disclosure.getClaimValue());
    }
}
