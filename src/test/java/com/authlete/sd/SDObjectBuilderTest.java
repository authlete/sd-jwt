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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import java.util.List;
import java.util.Map;
import org.junit.Test;


public final class SDObjectBuilderTest
{
    @SuppressWarnings("unchecked")
    @Test
    public void test_01_sd_nonsd()
    {
        // The following values are from the SD-JWT specification.
        Disclosure disclosure = Disclosure.parse("WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0");
        String expectedDigest = "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY";

        // Create an SDObjectBuilder instance with the default hash algorithm "sha-256".
        SDObjectBuilder builder = new SDObjectBuilder();

        // Add the digest of the disclosure.
        builder.putSDClaim(disclosure);

        // Add an arbitrary claim.
        String claimName  = "my_claim_name";
        String claimValue = "my_claim_value";
        builder.putClaim(claimName, claimValue);

        // Build a map that represents a JSON object.
        Map<String, Object> map = builder.build();

        // 1: "my_claim_name": "my_claim_value"
        // 2: "_sd": [ "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY" ]
        assertEquals(2, map.size());

        // "my_claim_name": "my_claim_value"

        assertTrue(map.containsKey(claimName));
        assertEquals(claimValue, map.get(claimName));

        // "_sd": [ "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY" ]

        assertTrue(map.containsKey(KEY_SD));
        Object sd = map.get(KEY_SD);

        assertTrue(sd instanceof List);
        List<String> digestList = (List<String>)sd;

        assertEquals(1, digestList.size());
        assertEquals(expectedDigest, digestList.get(0));
    }


    @SuppressWarnings("unchecked")
    @Test
    public void test_02_sd_sdalg()
    {
        // Create an SDObjectBuilder instance with the default hash algorithm "sha-256".
        SDObjectBuilder builder = new SDObjectBuilder();

        // Add a selectively disclosable claim.
        String claimName      = "my_claim_name";
        String claimValue     = "my_claim_value";
        Disclosure disclosure = builder.putSDClaim(claimName, claimValue);

        // Build a map that represents a JSON object which contains "_sd_alg"
        // in addition to "_sd".
        Map<String, Object> map = builder.build(/*hashAlgorithmIncluded*/true);

        // 1: "_sd"
        // 2: "_sd_alg"

        assertEquals(2, map.size());

        // "_sd"

        assertTrue(map.containsKey(KEY_SD));
        Object sd = map.get(KEY_SD);

        assertTrue(sd instanceof List);
        List<String> digestList = (List<String>)sd;

        // Digest of the disclosure with the default hash algorithm "sha-256".
        String expectedDigest = disclosure.digest();

        assertEquals(1, digestList.size());
        assertEquals(expectedDigest, digestList.get(0));

        // "_sd_alg"

        assertTrue(map.containsKey(KEY_SD_ALG));
        Object sdAlg = map.get(KEY_SD_ALG);

        assertTrue(sdAlg instanceof String);
        String algorithm = (String)sdAlg;

        assertEquals(builder.getHashAlgorithm(), algorithm);
    }


    @SuppressWarnings("unchecked")
    @Test
    public void test_03_duplicate_claim_names()
    {
        String claimName   = "my_claim_name";
        String claimValueA = "A";
        String claimValueB = "B";

        // Create two disclosures with the same claim name.
        Disclosure disclosureA = new Disclosure(claimName, claimValueA);
        Disclosure disclosureB = new Disclosure(claimName, claimValueB);

        // Create an SDObjectBuilder instance with the default hash algorithm "sha-256".
        SDObjectBuilder builder = new SDObjectBuilder();

        // Try to put digests of the two disclosures.
        // (But the first digest will be overwritten by the second one.)
        builder.putSDClaim(disclosureA);
        builder.putSDClaim(disclosureB);

        // Build a map that contains "_sd".
        Map<String, Object> map = builder.build();

        // "_sd"
        List<String> digestList = (List<String>)map.get(KEY_SD);

        // The number of elements in the "_sd" array should be 1 because
        // the digest value of disclosureA should be overwritten by the
        // digest value of disclosureB.
        assertEquals(1, digestList.size());
        assertEquals(disclosureB.digest(), digestList.get(0));
    }


    @Test
    public void test_04_duplicate_claim_names()
    {
        String claimName   = "my_claim_name";
        String claimValueA = "A";
        String claimValueB = "B";

        // Create an SDObjectBuilder instance with the default hash algorithm "sha-256".
        SDObjectBuilder builder = new SDObjectBuilder();

        // Put a digest of disclosure.
        builder.putSDClaim(claimName, claimValueA);

        // Put a normal claim. This operation will remove the digest which was added
        // by the above operation.
        builder.putClaim(claimName, claimValueB);

        // Build a map.
        Map<String, Object> map = builder.build();

        // The map should not contain the "_sd" array because the array is empty.
        assertFalse(map.containsKey(KEY_SD));

        // The map should contain a normal claim whose key is equal to claimName.
        assertTrue(map.containsKey(claimName));
        assertEquals(claimValueB, map.get(claimName));
    }


    @Test
    public void test_05_duplicate_claim_names()
    {
        String claimName   = "my_claim_name";
        String claimValueA = "A";
        String claimValueB = "B";

        // Create an SDObjectBuilder instance with the default hash algorithm "sha-256".
        SDObjectBuilder builder = new SDObjectBuilder();

        // Put a normal claim.
        builder.putClaim(claimName, claimValueA);

        // Put a digest of disclosure. This operation will remove the claim which was
        // added by the above operation.
        builder.putSDClaim(claimName, claimValueB);

        // Build a map that contains "_sd".
        Map<String, Object> map = builder.build();

        // The map should contain the "_sd" array only.
        assertTrue(map.containsKey(KEY_SD));
        assertEquals(1, map.size());
    }


    @SuppressWarnings("unchecked")
    @Test
    public void test_06_sha512()
    {
        // Create a Disclosure.
        String salt           = "_26bc4LT-ac6q2KI6cBW5es";
        String claimName      = "family_name";
        Object claimValue     = "Möbius";
        Disclosure disclosure = new Disclosure(salt, claimName, claimValue);

        // The hash algorithm to use.
        String hashAlgorithm = "sha-512";

        // Create an SDObjectBuilder with the hash algorithm to use.
        SDObjectBuilder builder = new SDObjectBuilder(hashAlgorithm);

        // Put a digest of the Disclosure.
        builder.putSDClaim(disclosure);

        // Create a Map instance with the "_sd_alg" claim included.
        Map<String, Object> map = builder.build(true);

        // "_sd_alg"
        assertTrue(map.containsKey(KEY_SD_ALG));
        assertEquals(hashAlgorithm, map.get(KEY_SD_ALG));

        // The digest value.
        assertTrue(map.containsKey(KEY_SD));
        List<String> digestList = (List<String>)map.get(KEY_SD);
        String digest = digestList.get(0);

        // The length of the base64url-encoded digest value computed with
        // "sha-512" should be 86.
        assertEquals(86, digest.length());
    }


    @SuppressWarnings("unchecked")
    @Test
    public void test_07_array()
    {
        String arrayName = "array";

        SDObjectBuilder builder = new SDObjectBuilder();

        builder.putSDClaim(arrayName, 0, "element0");
        builder.putSDClaim(arrayName, 1, "element1");

        Map<String, Object> map = builder.build();

        // The list of digests.
        assertTrue(map.containsKey(KEY_SD));
        List<String> digestList = (List<String>)map.get(KEY_SD);

        // The digest list should have two elements because a digest should
        // be generated for each array element.
        assertEquals(2, digestList.size());

        // The map should not contain other elements than "_sd".
        assertEquals(1, map.size());

        //--------------------------------------------------

        // Overwrite the element at the index 1.
        builder.putSDClaim(arrayName, 1, "element1_");

        // Rebuild.
        map = builder.build();

        // The number of elements in the digest list should not change.
        digestList = (List<String>)map.get(KEY_SD);
        assertEquals(2, digestList.size());

        //--------------------------------------------------

        // Remove digests for the array elements by putting a plain JSON array.
        builder.putClaim(arrayName, List.of("element0", "element1"));

        // Rebuild.
        map = builder.build();

        // The map should not contain "_sd".
        assertFalse(map.containsKey(KEY_SD));

        // Instead, the map should contain "array".
        assertTrue(map.containsKey(arrayName));

        //--------------------------------------------------

        // Remove the array by putting the digest of a disclosure that
        // represents an element of the array.
        builder.putSDClaim(arrayName, 2, "element2");

        // Rebuild.
        map = builder.build();

        // The map should contain "_sd".
        assertTrue(map.containsKey(KEY_SD));
        digestList = (List<String>)map.get(KEY_SD);

        // The digest list should have one element.
        assertEquals(1, digestList.size());

        // The "array" should not exist.
        assertFalse(map.containsKey(arrayName));
    }
}
