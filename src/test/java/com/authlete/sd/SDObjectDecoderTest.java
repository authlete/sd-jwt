/*
 * Copyright (C) 2023-2025 Authlete, Inc.
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


import static com.authlete.sd.CollectionUtility.listOf;
import static com.authlete.sd.CollectionUtility.mapOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.junit.Test;


public final class SDObjectDecoderTest
{
    @Test
    public void test_01_map()
    {
        List<String> sublist = listOf(
                "element-1",
                "element-2"
        );

        Map<String, String> submap = mapOf(
                "sub-key-1", "sub-value-1",
                "sub-key-2", "sub-value-2"
        );

        Map<String, Object> originalMap = mapOf(
                "key-1", "value-1",
                "key-2", sublist,
                "key-3", submap
        );

        // Prepare an encoded map and accompanying disclosures.
        SDObjectEncoder encoder = new SDObjectEncoder();
        Map<String, Object> encodedMap = encoder.encode(originalMap);
        List<Disclosure> disclosures   = encoder.getDisclosures();

        // A decoder and work variables.
        SDObjectDecoder decoder = new SDObjectDecoder();
        Collection<Disclosure> disclosed;
        Map<String, Object> decodedMap;
        Map<String, Object> expectedMap;

        // Disclose all. The original map should be restored.
        disclosed   = disclosures;
        decodedMap  = decoder.decode(encodedMap, disclosed);
        expectedMap = originalMap;
        assertEquals(expectedMap, decodedMap);

        // Disclose none. Only empty "key-2" and "key-3" should be contained.
        disclosed   = null;
        decodedMap  = decoder.decode(encodedMap, disclosed);
        expectedMap = mapOf("key-2", listOf(), "key-3", mapOf());
        assertEquals(expectedMap, decodedMap);

        // Disclose "key-1" only.
        disclosed   = filter(disclosures, d -> "key-1".equals(d.getClaimName()));
        decodedMap  = decoder.decode(encodedMap, disclosed);
        expectedMap = mapOf("key-1", "value-1", "key-2", listOf(), "key-3", mapOf());
        assertEquals(expectedMap, decodedMap);

        // Disclose array elements only.
        disclosed   = filter(disclosures, d -> d.getClaimName() == null);
        decodedMap  = decoder.decode(encodedMap, disclosed);
        expectedMap = mapOf("key-2", sublist, "key-3", mapOf());
        assertEquals(expectedMap, decodedMap);

        // Disclose key-value pairs in the sub map only.
        disclosed   = filter(disclosures, d -> d.getClaimName() != null && d.getClaimName().startsWith("sub-key-"));
        decodedMap  = decoder.decode(encodedMap, disclosed);
        expectedMap = mapOf("key-2", listOf(), "key-3", submap);
        assertEquals(expectedMap, decodedMap);
    }


    @Test
    public void test_02_list()
    {
        List<String> sublist = listOf(
                "sub-element-1",
                "sub-element-2"
        );

        Map<String, String> submap = mapOf(
                "sub-key-1", "sub-value-1",
                "sub-key-2", "sub-value-2"
        );

        List<Object> originalList = listOf(
                "element-1",
                sublist,
                submap
        );

        // Prepare an encoded list and accompanying disclosures.
        SDObjectEncoder encoder = new SDObjectEncoder();
        List<Object> encodedList     = encoder.encode(originalList);
        List<Disclosure> disclosures = encoder.getDisclosures();

        // A decoder and work variables.
        SDObjectDecoder decoder = new SDObjectDecoder();
        Collection<Disclosure> disclosed;
        List<Object> decodedList;
        List<Object> expectedList;

        // Disclose all. The original list should be restored.
        disclosed    = disclosures;
        decodedList  = decoder.decode(encodedList, disclosed);
        expectedList = originalList;
        assertEquals(expectedList, decodedList);

        // Disclose none. Only an empty list and an empty map should be restored.
        disclosed    = null;
        decodedList  = decoder.decode(encodedList, disclosed);
        expectedList = listOf(listOf(), mapOf());
        assertEquals(expectedList, decodedList);

        // Disclose "element-1" only.
        disclosed    = filter(disclosures, d -> "element-1".equals(d.getClaimValue()));
        decodedList  = decoder.decode(encodedList, disclosed);
        expectedList = listOf("element-1", listOf(), mapOf());
        assertEquals(expectedList, decodedList);

        // Disclose elements in the sub array only.
        disclosed    = filter(disclosures, d -> ((String)d.getClaimValue()).startsWith("sub-element-"));
        decodedList  = decoder.decode(encodedList, disclosed);
        expectedList = listOf(sublist, mapOf());
        assertEquals(expectedList, decodedList);

        // Disclose key-value pairs in the sub map only.
        disclosed   = filter(disclosures, d -> d.getClaimName() != null && d.getClaimName().startsWith("sub-key-"));
        decodedList  = decoder.decode(encodedList, disclosed);
        expectedList = listOf(listOf(), submap);
        assertEquals(expectedList, decodedList);
    }


    private static List<Disclosure> filter(List<Disclosure> disclosures, Predicate<? super Disclosure> predicate)
    {
        return disclosures.stream().filter(predicate).collect(Collectors.toList());
    }


    @SuppressWarnings("unchecked")
    @Test
    public void test_03_nested_map()
    {
        String PLACE_OF_BIRTH = "place_of_birth";
        String COUNTRY        = "country";
        String COUNTRY_VALUE  = "DD";

        // {"country": "DD"}
        SDObjectBuilder nestedMapBuilder = new SDObjectBuilder();
        Disclosure      nestedDisclosure = new Disclosure(COUNTRY, COUNTRY_VALUE);
        nestedMapBuilder.putSDClaim(nestedDisclosure);
        Map<String, Object> nestedMap    = nestedMapBuilder.build();

        // {"place_of_birth": {"country": "DD"}}
        SDObjectBuilder topMapBuilder = new SDObjectBuilder();
        Disclosure      topDisclosure = new Disclosure(PLACE_OF_BIRTH, nestedMap);
        topMapBuilder.putSDClaim(topDisclosure);
        Map<String, Object> topMap    = topMapBuilder.build();

        // Decode the map.
        SDObjectDecoder decoder = new SDObjectDecoder();
        Map<String, Object> decodedMap = decoder.decode(topMap, listOf(topDisclosure, nestedDisclosure));

        // The top map should contain the "place_of_birth" property and
        // its value should be a map.
        Object pob = decodedMap.get(PLACE_OF_BIRTH);
        assertTrue(pob instanceof Map);

        // The "place_of_birth" map should contain the "country" property and
        // its value should be a string.
        Object country = ((Map<String, Object>)pob).get(COUNTRY);
        assertTrue(country instanceof String);

        // The value of the "country" property should be "DD".
        assertEquals(COUNTRY_VALUE, country);
    }


    @SuppressWarnings("unchecked")
    @Test
    public void test_04_array_element()
    {
        String NATIONALITIES = "nationalities";
        String FR = "FR";
        String JP = "JP";

        // Create selectively-disclosable array elements which represent
        // country codes for France ("FR") and Japan ("JP").
        Disclosure frDisclosure = new Disclosure(FR);
        Disclosure jpDisclosure = new Disclosure(JP);

        // {
        //   "nationalities": [
        //     {"...", "??????????"},    <-- "FR"
        //     {"...", "??????????"}     <-- "JP"
        //   ]
        // }
        Map<String, Object> encodedMap = mapOf(
                NATIONALITIES, listOf(
                        frDisclosure.toArrayElement(),
                        jpDisclosure.toArrayElement()
                )
        );

        // Decode the map.
        SDObjectDecoder decoder = new SDObjectDecoder();
        Map<String, Object> decodedMap = decoder.decode(encodedMap, listOf(frDisclosure, jpDisclosure));

        // "nationalities"
        Object nationalities = decodedMap.get(NATIONALITIES);
        assertTrue(nationalities instanceof List);

        // "FR"
        Object first = ((List<?>)nationalities).get(0);
        assertEquals(FR, first);

        // "JP"
        Object second = ((List<?>)nationalities).get(1);
        assertEquals(JP, second);
    }
}
