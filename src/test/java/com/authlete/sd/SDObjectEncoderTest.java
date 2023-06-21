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


import static com.authlete.sd.SDConstants.KEY_SD;
import static com.authlete.sd.SDConstants.KEY_SD_ALG;
import static com.authlete.sd.SDConstants.KEY_THREE_DOTS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import org.junit.Test;


public final class SDObjectEncoderTest
{
    @Test
    public void test_01_map()
    {
        List<String> sublist = List.of(
                "element-1",
                "element-2"
        );

        Map<String, String> submap = Map.of(
                "sub-key-1", "sub-value-1",
                "sub-key-2", "sub-value-2"
        );

        Map<String, Object> originalMap = Map.of(
                "key-1", "value-1",
                "key-2", sublist,
                "key-3", submap
        );

        // Encoder
        SDObjectEncoder encoder = new SDObjectEncoder();

        // Encode
        Map<String, Object> encodedMap = encoder.encode(originalMap);
        List<Disclosure> disclosures   = encoder.getDisclosures();

        // "_sd_alg" should be contained (cf. setHashAlgorithmIncluded(boolean))
        assertTrue(encodedMap.containsKey(KEY_SD_ALG));

        // "_sd" should be contained.
        assertTrue(encodedMap.containsKey(KEY_SD));

        // "key-1" should not be contained.
        assertFalse(encodedMap.containsKey("key-1"));

        // "key-2" should be contained.
        assertTrue(encodedMap.containsKey("key-2"));

        // "key-3" should be contained.
        assertTrue(encodedMap.containsKey("key-3"));

        // Work variables
        int count;
        Disclosure disclosure;

        // The number of disclosures.
        count = 1 + sublist.size() + submap.size();
        assertEquals(count, disclosures.size());

        // Disclosure: key-1
        disclosure = find(disclosures, d -> "key-1".equals(d.getClaimName()));
        assertNotNull(disclosure);
        assertEquals("value-1", disclosure.getClaimValue());

        // Disclosure: element-1
        disclosure = find(disclosures, d -> "element-1".equals(d.getClaimValue()));
        assertNotNull(disclosure);
        assertNull(disclosure.getClaimName());

        // Disclosure: element-2
        disclosure = find(disclosures, d -> "element-2".equals(d.getClaimValue()));
        assertNotNull(disclosure);
        assertNull(disclosure.getClaimName());

        // Disclosure: sub-key-1
        disclosure = find(disclosures, d -> "sub-key-1".equals(d.getClaimName()));
        assertNotNull(disclosure);
        assertEquals("sub-value-1", disclosure.getClaimValue());

        // Disclosure: sub-key-2
        disclosure = find(disclosures, d -> "sub-key-2".equals(d.getClaimName()));
        assertNotNull(disclosure);
        assertEquals("sub-value-2", disclosure.getClaimValue());
    }


    @SuppressWarnings("unchecked")
    @Test
    public void test_02_list()
    {
        List<String> sublist = List.of(
                "sub-element-1",
                "sub-element-2"
        );

        Map<String, String> submap = Map.of(
                "sub-key-1", "sub-value-1",
                "sub-key-2", "sub-value-2"
        );

        List<Object> originalList = List.of(
                "element-1",
                sublist,
                submap
        );

        // Encoder without decoy generation.
        SDObjectEncoder encoder = new SDObjectEncoder(0.0, 0.0);

        // Encode
        List<Object> encodedList     = encoder.encode(originalList);
        List<Disclosure> disclosures = encoder.getDisclosures();

        // Work variables
        Object element;
        String digest;
        List<?> list;
        Map<String, Object> map;
        Disclosure disclosure;

        //
        // Element at index 0
        //
        //     { "...": "<digest>" }
        //
        element = encodedList.get(0);

        digest     = extractDigest(element);
        disclosure = findByDigest(disclosures, digest);

        assertNotNull(disclosure);
        assertNull(disclosure.getClaimName());
        assertEquals("element-1", disclosure.getClaimValue());

        //
        // Element at index 1
        //
        //     [ { "...": "<digest>" }, { "...": "<digest>" } ]
        //
        element = encodedList.get(1);

        assertTrue(element instanceof List);
        list = (List<?>)element;

        assertEquals(2, list.size());

        digest     = extractDigest(list.get(0));
        disclosure = findByDigest(disclosures, digest);

        assertNotNull(disclosure);
        assertNull(disclosure.getClaimName());
        assertEquals("sub-element-1", disclosure.getClaimValue());

        digest     = extractDigest(list.get(1));
        disclosure = findByDigest(disclosures, digest);

        assertNotNull(disclosure);
        assertNull(disclosure.getClaimName());
        assertEquals("sub-element-2", disclosure.getClaimValue());

        //
        // Element at index 2
        //
        //     {
        //       "_sd": [
        //         "<digest>",
        //         "<digest>"
        //       ]
        //     }
        //
        element = encodedList.get(2);

        assertTrue(element instanceof Map);
        map = (Map<String, Object>)element;

        assertTrue(map.containsKey(KEY_SD));
        assertTrue(map.get(KEY_SD) instanceof List);
        list = (List<?>)map.get(KEY_SD);

        assertEquals(2, list.size());

        Disclosure disclosureA = findByDigest(disclosures, (String)list.get(0));
        Disclosure disclosureB = findByDigest(disclosures, (String)list.get(1));

        assertNotNull(disclosureA);
        assertNotNull(disclosureB);

        Disclosure disclosure1;
        Disclosure disclosure2;

        if ("sub-key-1".equals(disclosureA.getClaimName()))
        {
            disclosure1 = disclosureA;
            disclosure2 = disclosureB;
        }
        else
        {
            disclosure1 = disclosureB;
            disclosure2 = disclosureA;
        }

        assertEquals("sub-key-1",   disclosure1.getClaimName());
        assertEquals("sub-value-1", disclosure1.getClaimValue());

        assertEquals("sub-key-2",   disclosure2.getClaimName());
        assertEquals("sub-value-2", disclosure2.getClaimValue());
    }


    @Test
    public void test_03_retained_claims()
    {
        Map<String, Object> originalMap = Map.of(
                "iss", "issuer",
                "iat", 123,
                "custom-key", "custom-value"
        );

        // Encoder
        SDObjectEncoder encoder = new SDObjectEncoder();

        // Encode
        Map<String, Object> encodedMap = encoder.encode(originalMap);

        // "iss" and "iat" should be retained.
        assertTrue(encodedMap.containsKey("iss"));
        assertTrue(encodedMap.containsKey("iat"));

        // "custom-key" should not be retained.
        assertFalse(encodedMap.containsKey("custom-key"));

        // Adjust the set of retained claims.
        encoder.getRetainedClaims().remove("iat");
        encoder.getRetainedClaims().add("custom-key");

        // Encode again with the new settings.
        encodedMap = encoder.encode(originalMap);

        // "iss" should be retained.
        assertTrue(encodedMap.containsKey("iss"));

        // "iat" should not be retained.
        assertFalse(encodedMap.containsKey("iat"));

        // "custom-key" should be retained.
        assertTrue(encodedMap.containsKey("custom-key"));
    }


    private static Disclosure find(List<Disclosure> disclosures, Predicate<? super Disclosure> predicate)
    {
        return disclosures.stream().filter(predicate).findFirst().orElse(null);
    }


    private static Disclosure findByDigest(List<Disclosure> disclosures, final String digest)
    {
        return find(disclosures, d -> d.digest().equals(digest));
    }


    @SuppressWarnings("unchecked")
    private static String extractDigest(Object element)
    {
        // { "...": "<digest>" }

        assertTrue(element instanceof Map);
        Map<String, Object> map = (Map<String, Object>)element;

        assertTrue(map.containsKey(KEY_THREE_DOTS));
        assertTrue(map.get(KEY_THREE_DOTS) instanceof String);
        String digest = (String)map.get(KEY_THREE_DOTS);

        assertNotNull(digest);

        return digest;
    }
}
