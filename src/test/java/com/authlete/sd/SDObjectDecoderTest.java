/*
 * Copyright (C) 2023-2026 Authlete, Inc.
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
import static org.junit.Assert.fail;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.junit.Test;
import com.nimbusds.jwt.SignedJWT;


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


    @SuppressWarnings("unchecked")
    @Test
    public void test_05_nested_array()
    {
        List<Disclosure> disclosures = new ArrayList<>();

        // {
        //   "propertyA": [
        //     "$.propertyA[0]",
        //     [
        //       "$.propertyA[1][0]",
        //       [
        //         "$.propertyA[1][1][0]"
        //       ],
        //       {
        //         "propertyB": "$.propertyA[1][2].propertyB",
        //         "propertyC": [
        //           "$.propertyA[1][2].propertyC[0]",
        //           [
        //             "$.propertyA[1][2].propertyC[1][0]"
        //           ],
        //           {
        //             "propertyD": "$.propertyA[1][2].propertyC[2].propertyD"
        //           }
        //         ]
        //       }
        //     ]
        //   ]
        // }
        // @formatter:off
        Map<String, Object> encodedMap = encodeMap(disclosures, mapOf(       // {
          "propertyA", encodeList(disclosures, listOf(                       //   "propertyA": [
            "$.propertyA[0]",                                                //     "$.propertyA[0]",
            encodeList(disclosures, listOf(                                  //     [
              "$.propertyA[1][0]",                                           //       "$.propertyA[1][0]",
              encodeList(disclosures, listOf(                                //       [
                "$.propertyA[1][1][0]"                                       //         $.propertyA[1][1][0]
              )),                                                            //       ],
              encodeMap(disclosures, mapOf(                                  //       {
                "propertyB", "$.propertyA[1][2].propertyB",                  //         "propertyB": "$.propertyA[1][2].propertyB",
                "propertyC", encodeList(disclosures, listOf(                 //         "propertyC": [
                  "$.propertyA[1][2].propertyC[0]",                          //           "$.propertyA[1][2].propertyC[0]",
                  encodeList(disclosures, listOf(                            //           [
                    "$.propertyA[1][2].propertyC[1][0]"                      //             "$.propertyA[1][2].propertyC[1][0]"
                  )),                                                        //           ],
                  encodeMap(disclosures, mapOf(                              //           {
                    "propertyD", "$.propertyA[1][2].propertyC[2].propertyD"  //             "propertyD", "$.propertyA[1][2].propertyC[2].propertyD"
                  ))                                                         //           }
                ))                                                           //         ]
              ))                                                             //       }
            ))                                                               //     ]
          ))                                                                 //   ]
        ));                                                                  // }
        // @formatter:on

        // Decode the map.
        SDObjectDecoder decoder = new SDObjectDecoder();
        Map<String, Object> decodedMap = decoder.decode(encodedMap, disclosures);

        // propertyA
        assertTrue(decodedMap.get("propertyA") instanceof List);
        List<Object> propertyA = (List<Object>)decodedMap.get("propertyA");
        assertEquals(2, propertyA.size());

        // propertyA[0]
        assertTrue(propertyA.get(0) instanceof String);
        assertEquals("$.propertyA[0]", propertyA.get(0));

        // propertyA[1]
        assertTrue(propertyA.get(1) instanceof List);
        List<Object> propertyA1 = (List<Object>)propertyA.get(1);
        assertEquals(3, propertyA1.size());

        // propertyA[1][0]
        assertTrue(propertyA1.get(0) instanceof String);
        assertEquals("$.propertyA[1][0]", propertyA1.get(0));

        // propertyA[1][1]
        assertTrue(propertyA1.get(1) instanceof List);
        List<Object> propertyA11 = (List<Object>)propertyA1.get(1);
        assertEquals(1, propertyA11.size());

        // propertyA[1][1][0]
        assertTrue(propertyA11.get(0) instanceof String);
        assertEquals("$.propertyA[1][1][0]", propertyA11.get(0));

        // propertyA[1][2]
        assertTrue(propertyA1.get(2) instanceof Map);
        Map<String, Object> propertyA12 = (Map<String, Object>)propertyA1.get(2);
        assertEquals(2, propertyA12.size());

        // propertyA[1][2].propertyB
        assertTrue(propertyA12.get("propertyB") instanceof String);
        assertEquals("$.propertyA[1][2].propertyB", propertyA12.get("propertyB"));

        // propertyA[1][2].propertyC
        assertTrue(propertyA12.get("propertyC") instanceof List);
        List<Object> propertyC = (List<Object>)propertyA12.get("propertyC");
        assertEquals(3, propertyC.size());

        // propertyA[1][2].propertyC[0]
        assertTrue(propertyC.get(0) instanceof String);
        assertEquals("$.propertyA[1][2].propertyC[0]", propertyC.get(0));

        // propertyA[1][2].propertyC[1]
        assertTrue(propertyC.get(1) instanceof List);
        List<Object> propertyC1 = (List<Object>)propertyC.get(1);
        assertEquals(1, propertyC1.size());

        // propertyA[1][2].propertyC[1][0]
        assertTrue(propertyC1.get(0) instanceof String);
        assertEquals("$.propertyA[1][2].propertyC[1][0]", propertyC1.get(0));

        // propertyA[1][2].propertyC[2]
        assertTrue(propertyC.get(2) instanceof Map);
        Map<String, Object> propertyC2 = (Map<String, Object>)propertyC.get(2);
        assertEquals(1, propertyC2.size());

        // propertyA[1][2].propertyC[2].propertyD
        assertTrue(propertyC2.get("propertyD") instanceof String);
        assertEquals("$.propertyA[1][2].propertyC[2].propertyD", propertyC2.get("propertyD"));
    }


    private static SDObjectEncoder createEncoder()
    {
        return new SDObjectEncoder()
                .noDecoy()
                .setHashAlgorithmIncluded(false)
                ;
    }


    private static List<Object> encodeList(List<Disclosure> disclosures, List<?> list)
    {
        SDObjectEncoder encoder = createEncoder();

        // Encode the given list.
        List<Object> encodedList = encoder.encode(list, /*recursive*/ false);

        // Accumulate  disclosures.
        disclosures.addAll(encoder.getDisclosures());

        // Return the encoded list.
        return encodedList;
    }


    private static Map<String, Object> encodeMap(List<Disclosure> disclosures, Map<String, Object> map)
    {
        SDObjectEncoder encoder = createEncoder();

        // Encode the given map.
        Map<String, Object> encodedMap = encoder.encode(map, /*recursive*/ false);

        // Accumulate disclosures.
        disclosures.addAll(encoder.getDisclosures());

        // Return the encoded map.
        return encodedMap;
    }


    @Test
    @SuppressWarnings("unchecked")
    public void test_06_issue_8()
    {
        // [Issue 8] Recursive array objects other than leaf elements not correctly decoded
        // https://github.com/authlete/sd-jwt/issues/8

        // Decode the sample as an SD-JWT.
        SDJWT sdJwt = SDJWT.parse(
                "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXh" +
                "hbXBsZTppc3N1ZXIiLCJfc2QiOlsiTWtuTi0zVWtJem9ka3RfeGZKVDd4VTQ2Qjh" +
                "oTGdleE1oNWZlQlNjRE1aTSJdLCJpYXQiOjE3Nzc1MDcyMDAsInZjdCI6InVybjp" +
                "2Y3Q6dGVzdDoxIiwiX3NkX2FsZyI6InNoYS0yNTYifQ.Uo8LYu84xjxG6Z9rjcV8" +
                "LMdhnE-JUEg_y3vwBjblhgcqfGJ_enXMUmzn0aYeuttYlgSFs3ruxkhdWoWLMlZY" +
                "yw~WyJFdENBa3ZOdjF2OS01cUpCSFZkTXZ3IiwxXQ~WyJqMVN4RGNlVXk0Vmx2Vz" +
                "FJSVlTdjlRIiwzLjE0XQ~WyJYalBtVUJjV0REa3JFNGpya1B1Z3RBIiwic3RyaW5" +
                "nIl0~WyJSQXlZYXVia203Z2pxWmFVbmRfaE5nIiwwXQ~WyI4bEpWWXRMT2ZpR00w" +
                "OEpocnAwZ0p3IixbeyIuLi4iOiJCUGpvaWdNUlhVbDV2eTBLZ2VEVGdFamZDUkhO" +
                "VHVueDNtREdaOWtpWVhNIn1dXQ~WyJZM3J5T2JRNHVLS3QtX2szLTdITG9RIiwxX" +
                "Q~WyJhTmU2R2UwTi0zNExPMS1JbGQzWGlRIixbeyIuLi4iOiJFVnBscmlhRWhqM3" +
                "hyZkdhSW1sNE1ERWpJTGNkNVVOQVZudUU5TUVOM2FRIn1dXQ~WyJBSG1yNFd0R2R" +
                "hbVA0SjVoRVlmdXF3IiwyXQ~WyI1TVJYTW9NN0VnQzJRa0t2ei1NaE53IixbeyIu" +
                "Li4iOiI0Z0NlTGJwVFdEdjNUZ0xNYTVfZzkxSkVFN09hSlZ0WWRzclV0Yk5JaFI4" +
                "In1dXQ~WyJ5NGwtVndoREtYbTRod3FsajY1MDN3IiwiY2xhaW0iLCJOZXN0ZWQgZ" +
                "WxlbWVudCJd~WyJndjBGNFdPamtqLUlkdjY1d0k5V2VnIiwiZGVlcGx5IiwibmVz" +
                "dGVkIl0~WyJFbUpJbHZvaTdxUlI4U3pnMk9Lci1nIiwib3RoZXIiLHsiX3NkIjpb" +
                "InZwMmhvYzROeGhuOUM2aXRaMDdMSl9CWEdMUC1CVnp3WmdsQWtmTEcwWXciXX1d" +
                "~WyJFUGQ5ZVIwa2lOS21pSmFxTXdlc0RnIix7Il9zZCI6WyJKbXZ6M29aMWxPZHd" +
                "jNXQ1cGFFaTE3SjdXLU0yOElEUzVQRUJSd2hudFpBIiwid3FYaklGLTJhZEdyYXh" +
                "KSHRKa1ZERTVYVmNCRVRaRU94LW5fTGNQUmFPVSJdfV0~WyJtNkFicUZiYUdnM1N" +
                "3MUJtc2phVkNBIiwiYXJyYXlfYXJyYXlzIixbeyIuLi4iOiJTM0FILW1PQXU0T2t" +
                "raVp5dTNSeThYS05JWm5LVGR0dGkwRklqMUlHVWNRIn0seyIuLi4iOiJsc1dPbl9" +
                "WdVpwSUJjejZscXhNZWMwbTdnemtoNXVlZWxZVEdMb3NsTVdNIn0seyIuLi4iOiJ" +
                "6elNuaWxXWEZtMzh1eGFzcmdzeDUycUZZZk1HR2VCcWJkc0gzaTg3ZElVIn0seyI" +
                "uLi4iOiJ1ZEZrQUZ1bUMtSXJUNVY3dmFibUlpeFpXaTNFOFNYYTQ2RkkzR003bTZ" +
                "rIn0seyIuLi4iOiJpTDNQdkZISUZxN1R3RGRDMzByM2JMNXJEenhLc3dGRFVmYVJ" +
                "uMjJycHVBIn0seyIuLi4iOiJRQTBUU0N5c3dMeDc0UzY5QWUzdno4TUVvTm1wa3J" +
                "zUWRHR1FGUGM2RDZZIn0seyIuLi4iOiJnaTNfRFZ2QVpBdHB2Q24zOWR4d1BVV1l" +
                "jT2VCS1dvcGU2SklENmJ6VzFvIn1dXQ~WyJIMmF0aXZ2cmctUng3bEkzUVpXa0VR" +
                "Iiwib2JqZWN0Iix7Il9zZCI6WyJzcmJtZ254MkluNW5uRC1BS2V4SWZDTVNqVmlj" +
                "YXh6ZFcyQy1GRmpfVVRVIl19XQ~");

        // Extract the payload of the credential JWT in the SD-JWT.
        Map<String, Object> encodedMap = extractCredentialJwtPayload(sdJwt);

        // Decode the map.
        SDObjectDecoder decoder = new SDObjectDecoder();
        Map<String, Object> decodedMap = decoder.decode(encodedMap, sdJwt.getDisclosures());

        // {
        //   "object": {
        //     "array_arrays": [
        //       1,
        //       3.14,
        //       "string",
        //       [0],
        //       [1],
        //       [2],
        //       {
        //         "claim": "Nested element",
        //         "other": {
        //           "deeply": "nested"
        //         }
        //       }
        //     ]
        //   }
        // }

        // object
        assertTrue(decodedMap.get("object") instanceof Map);
        Map<String, Object> object = (Map<String, Object>)decodedMap.get("object");

        // object.array_arrays
        assertTrue(object.get("array_arrays") instanceof List);
        List<Object> array_arrays = (List<Object>)object.get("array_arrays");
        assertEquals(7, array_arrays.size());

        // object.array_arrays[3]
        assertTrue(array_arrays.get(3) instanceof List);
        List<Object> array_arrays3 = (List<Object>)array_arrays.get(3);
        assertEquals(1, array_arrays3.size());

        // object.array_arrays[3][0]
        assertTrue(array_arrays3.get(0) instanceof Number);
        assertEquals(0, ((Number)array_arrays3.get(0)).intValue());

        // object.array_arrays[4]
        assertTrue(array_arrays.get(4) instanceof List);
        List<Object> array_arrays4 = (List<Object>)array_arrays.get(4);
        assertEquals(1, array_arrays4.size());

        // object.array_arrays[4][0]
        assertTrue(array_arrays4.get(0) instanceof Number);
        assertEquals(1, ((Number)array_arrays4.get(0)).intValue());

        // object.array_arrays[5]
        assertTrue(array_arrays.get(5) instanceof List);
        List<Object> array_arrays5 = (List<Object>)array_arrays.get(5);
        assertEquals(1, array_arrays5.size());

        // object.array_arrays[5][0]
        assertTrue(array_arrays5.get(0) instanceof Number);
        assertEquals(2, ((Number)array_arrays5.get(0)).intValue());

        // object.array_arrays[6]
        assertTrue(array_arrays.get(6) instanceof Map);
        Map<String, Object> array_arrays6 = (Map<String, Object>)array_arrays.get(6);
        assertEquals(2, array_arrays6.size());

        // object.array_arrays[6].claim
        assertTrue(array_arrays6.get("claim") instanceof String);
        assertEquals("Nested element", array_arrays6.get("claim"));

        // object.array_arrays[6].other
        assertTrue(array_arrays6.get("other") instanceof Map);
        Map<String, Object> other = (Map<String, Object>)array_arrays6.get("other");
        assertEquals(1, other.size());

        // object.array_arrays[6].other.deeply
        assertTrue(other.get("deeply") instanceof String);
        assertEquals("nested", other.get("deeply"));
    }


    private static Map<String, Object> extractCredentialJwtPayload(SDJWT sdJwt)
    {
        try
        {
            // Extract the payload part of the credential JWT in the SD-JWT as a Map.
            return SignedJWT.parse(sdJwt.getCredentialJwt()).getJWTClaimsSet().toJSONObject();
        }
        catch (ParseException cause)
        {
            fail("The payload of the SD-JWT or the SD-JWT itself is malformed: " + cause.getMessage());

            return null;
        }
    }
}
