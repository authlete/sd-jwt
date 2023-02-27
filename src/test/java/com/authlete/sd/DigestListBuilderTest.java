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


import static org.junit.Assert.assertEquals;
import java.util.List;
import org.junit.Test;


public final class DigestListBuilderTest
{
    @Test
    public void test_01_1_disclosure()
    {
        // The following values are from the SD-JWT specification.
        Disclosure disclosure = Disclosure.parse("WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0");
        String expectedDigest = "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY";

        // Create a DigestListBuilder instance with the default hash algorithm "sha-256".
        DigestListBuilder builder = new DigestListBuilder();

        // Add the digest of the disclosure. The addDisclosureDigest method
        // returns the digest value of the given disclosure which was computed
        // with the hash algorithm.
        String actualDigest = builder.addDisclosureDigest(disclosure);

        assertEquals(expectedDigest, actualDigest);

        // Build a list of digests.
        List<String> digestList = builder.build();

        assertEquals(1, digestList.size());
        assertEquals(expectedDigest, digestList.get(0));
    }


    @Test
    public void test_02_4_disclosures()
    {
        // The following values are from the SD-JWT specification.
        Disclosure streetAddressDisclosure = Disclosure.parse("WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd");
        String     streetAddressDigest     = "pEtkKwoFK_JHN7yNby0Lc_Jc10BAxCm5yXJjDbVehvU";
        Disclosure localityDisclosure      = Disclosure.parse("WyJXcEtIQmVTa3A5U2MyNVV4a1F1RmNRIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0");
        String     localityDigest          = "nTzPZ3Q68z1Ko_9ao9LK0mSYXY5gY6UG6KEkQ_BdqU0";
        Disclosure regionDisclosure        = Disclosure.parse("WyIzSl9xWGctdUwxYzdtN1FoT0hUNTJnIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd");
        String     regionDigest            = "9-VdSnvRTZNDo-4Bxcp3X-V9VtLOCRUkR6oLWZQl81I";
        Disclosure countryDisclosure       = Disclosure.parse("WyIwN2U3bWY2YWpTUDJjZkQ3NmJCZE93IiwgImNvdW50cnkiLCAiREUiXQ");
        String     countryDigest           = "7pHe1uQ5uSClgAxXdG0E6dKnBgXcxEO1zvoQO9E5Lr4";

        // Create a DigestListBuilder instance with the default hash algorithm "sha-256".
        DigestListBuilder builder = new DigestListBuilder();

        // Add digests of the disclosures.
        builder.addDisclosureDigest(streetAddressDisclosure);
        builder.addDisclosureDigest(localityDisclosure);
        builder.addDisclosureDigest(regionDisclosure);
        builder.addDisclosureDigest(countryDisclosure);

        // Build a list of digests.
        List<String> digestList = builder.build();

        assertEquals(4, digestList.size());

        // Note that the elements in the list are sorted.
        assertEquals(countryDigest,       digestList.get(0));
        assertEquals(regionDigest,        digestList.get(1));
        assertEquals(localityDigest,      digestList.get(2));
        assertEquals(streetAddressDigest, digestList.get(3));
    }


    @Test
    public void test_03_1_disclosure_2_decoys()
    {
        // The following values are from the SD-JWT specification.
        Disclosure disclosure = Disclosure.parse("WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0");

        // Create a DigestListBuilder instance with the default hash algorithm "sha-256".
        DigestListBuilder builder = new DigestListBuilder();

        // Add a disclosure digest and 2 decoy digests.
        builder.addDisclosureDigest(disclosure);
        builder.addDecoyDigests(2);

        // Build a list of digests.
        List<String> digestList = builder.build();

        assertEquals(3, digestList.size());
    }
}
