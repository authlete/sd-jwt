/*
 * Copyright (C) 2023-2024 Authlete, Inc.
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
import static org.junit.Assert.assertNull;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.Test;


public final class SDJWTTest
{
    @Test
    public void test_01_crjwt_only()
    {
        // Credential JWT
        String crJwt = "a.b.c";

        // SD-JWT with no disclosures.
        String input = String.format("%s~", crJwt);

        // Parse the input.
        SDJWT sdJwt = SDJWT.parse(input);

        // Credential JWT
        assertEquals(crJwt, sdJwt.getCredentialJwt());

        // Disclosures
        assertEquals(0, sdJwt.getDisclosures().size());

        // Binding JWT
        assertNull(sdJwt.getBindingJwt());

        // String representation
        assertEquals(input, sdJwt.toString());
    }


    @Test
    public void test_02_1_disclosure()
    {
        String crJwt = "a.b.c";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";

        // SD-JWT with 1 disclosure.
        String input = String.format("%s~%s~", crJwt, dc0);

        // Parse the input.
        SDJWT sdJwt = SDJWT.parse(input);

        // Credential JWT
        assertEquals(crJwt, sdJwt.getCredentialJwt());

        // Disclosures
        assertEquals(1, sdJwt.getDisclosures().size());

        Disclosure disclosure0 = sdJwt.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());

        // Binding JWT
        assertNull(sdJwt.getBindingJwt());

        // String representation
        assertEquals(input, sdJwt.toString());
    }


    @Test
    public void test_03_2_disclosures()
    {
        String crJwt = "a.b.c";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";
        String dc1   = "WyJXcEtIQmVTa3A5U2MyNVV4a1F1RmNRIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0";

        // SD-JWT with 2 disclosures.
        String input = String.format("%s~%s~%s~", crJwt, dc0, dc1);

        // Parse the input.
        SDJWT sdJwt = SDJWT.parse(input);

        // Credential JWT
        assertEquals(crJwt, sdJwt.getCredentialJwt());

        // Disclosures
        assertEquals(2, sdJwt.getDisclosures().size());

        Disclosure disclosure0 = sdJwt.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());

        Disclosure disclosure1 = sdJwt.getDisclosures().get(1);
        assertEquals(dc1, disclosure1.getDisclosure());

        // Binding JWT
        assertNull(sdJwt.getBindingJwt());

        // String representation
        assertEquals(input, sdJwt.toString());
    }


    @Test
    public void test_04_crjwt_bdjwt()
    {
        String crJwt = "a.b.c";
        String bdJwt = "d.e.f";

        // SD-JWT with no disclosures and a binding JWT.
        String input = String.format("%s~%s", crJwt, bdJwt);

        // Parse the input.
        SDJWT sdJwt = SDJWT.parse(input);

        // Credential JWT
        assertEquals(crJwt, sdJwt.getCredentialJwt());

        // Disclosures
        assertEquals(0, sdJwt.getDisclosures().size());

        // Binding JWT
        assertEquals(bdJwt, sdJwt.getBindingJwt());

        // String representation
        assertEquals(input, sdJwt.toString());
    }


    @Test
    public void test_05_1_disclosure_bdjwt()
    {
        String crJwt = "a.b.c";
        String bdJwt = "d.e.f";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";

        // SD-JWT with 1 disclosure and a binding JWT.
        String input = String.format("%s~%s~%s", crJwt, dc0, bdJwt);

        // Parse the input.
        SDJWT sdJwt = SDJWT.parse(input);

        // Credential JWT
        assertEquals(crJwt, sdJwt.getCredentialJwt());

        // Disclosures
        assertEquals(1, sdJwt.getDisclosures().size());

        Disclosure disclosure0 = sdJwt.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());

        // Binding JWT
        assertEquals(bdJwt, sdJwt.getBindingJwt());
    }


    @Test
    public void test_06_2_disclosures_bdjwt()
    {
        String crJwt = "a.b.c";
        String bdJwt = "d.e.f";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";
        String dc1   = "WyJXcEtIQmVTa3A5U2MyNVV4a1F1RmNRIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0";

        // SD-JWT with 2 disclosures and a binding JWT.
        String input = String.format("%s~%s~%s~%s", crJwt, dc0, dc1, bdJwt);

        // Parse the input.
        SDJWT sdJwt = SDJWT.parse(input);

        // Credential JWT
        assertEquals(crJwt, sdJwt.getCredentialJwt());

        // Disclosures
        assertEquals(2, sdJwt.getDisclosures().size());

        Disclosure disclosure0 = sdJwt.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());

        Disclosure disclosure1 = sdJwt.getDisclosures().get(1);
        assertEquals(dc1, disclosure1.getDisclosure());

        // Binding JWT
        assertEquals(bdJwt, sdJwt.getBindingJwt());

        // String representation
        assertEquals(input, sdJwt.toString());
    }


    @Test
    public void test_sd_hash()
    {
        // From the SD-JWT specification.
        String sdJwtStr =
                "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCJ9.eyJfc2QiOiBbIjBIWm1"
                + "uU0lQejMzN2tTV2U3QzM0bC0tODhnekppLWVCSjJWel9ISndBVGciLCAiOVpicGxDN1R"
                + "kRVc3cWFsNkJCWmxNdHFKZG1lRU9pWGV2ZEpsb1hWSmRSUSIsICJJMDBmY0ZVb0RYQ3V"
                + "jcDV5eTJ1anFQc3NEVkdhV05pVWxpTnpfYXdEMGdjIiwgIklFQllTSkdOaFhJbHJRbzU"
                + "4eWtYbTJaeDN5bGw5WmxUdFRvUG8xN1FRaVkiLCAiTGFpNklVNmQ3R1FhZ1hSN0F2R1R"
                + "yblhnU2xkM3o4RUlnX2Z2M2ZPWjFXZyIsICJodkRYaHdtR2NKUXNCQ0EyT3RqdUxBY3d"
                + "BTXBEc2FVMG5rb3ZjS09xV05FIiwgImlrdXVyOFE0azhxM1ZjeUE3ZEMtbU5qWkJrUmV"
                + "EVFUtQ0c0bmlURTdPVFUiLCAicXZ6TkxqMnZoOW80U0VYT2ZNaVlEdXZUeWtkc1dDTmc"
                + "wd1RkbHIwQUVJTSIsICJ3elcxNWJoQ2t2a3N4VnZ1SjhSRjN4aThpNjRsbjFqb183NkJ"
                + "DMm9hMXVnIiwgInpPZUJYaHh2SVM0WnptUWNMbHhLdUVBT0dHQnlqT3FhMXoySW9WeF9"
                + "ZRFEiXSwgImlzcyI6ICJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsICJpYXQiOiA"
                + "xNjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgInZjdCI6ICJodHRwczovL2JtaS5"
                + "idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwgImFnZV9lcXVhbF9vcl9vdmV"
                + "yIjogeyJfc2QiOiBbIkZjOElfMDdMT2NnUHdyREpLUXlJR085N3dWc09wbE1Makh2UkM"
                + "0UjQtV2ciLCAiWEx0TGphZFVXYzl6Tl85aE1KUm9xeTQ2VXNDS2IxSXNoWnV1cVVGS1N"
                + "DQSIsICJhb0NDenNDN3A0cWhaSUFoX2lkUkNTQ2E2NDF1eWNuYzh6UGZOV3o4bngwIiw"
                + "gImYxLVAwQTJkS1dhdnYxdUZuTVgyQTctRVh4dmhveHY1YUhodUVJTi1XNjQiLCAiazV"
                + "oeTJyMDE4dnJzSmpvLVZqZDZnNnl0N0Fhb25Lb25uaXVKOXplbDNqbyIsICJxcDdaX0t"
                + "5MVlpcDBzWWdETzN6VnVnMk1GdVBOakh4a3NCRG5KWjRhSS1jIl19LCAiX3NkX2FsZyI"
                + "6ICJzaGEtMjU2IiwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlA"
                + "tMjU2IiwgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkN"
                + "lR2VtYyIsICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ"
                + "5RjJIWlEifX19.Zkigt10NnCN2ZKjHUZ9Jo-1cJ2ULBz4lNu4dv1ZTR_cFg2lT9-6zJX"
                + "I-LMtpnA5HuvrWXeyYJBxiqvoTw128ag~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiw"
                + "gIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d~WyJNMEpiNTd0NDF1YnJrU3V5ckRUM3hBIi"
                + "wgIjE4IiwgdHJ1ZV0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub"
                + "25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wb"
                + "GUub3JnIiwgImlhdCI6IDE3MzE2OTYyOTksICJzZF9oYXNoIjogInRhcW9uTjJnWkhIe"
                + "lI4VWJIcUZmMG9GTjFrTm1PVzZBdlYzQUp4bjNXTncifQ.BraAy1HQ2rHF6WyG1gtnnf"
                + "tqJIVkNMTfrWXWsTqaZ7anoaHKPBcbBegET5c0IAHMjQOIkj7xFL4mWmf5gjQlww"
                ;

        // Parse
        SDJWT sdJwt = SDJWT.parse(sdJwtStr);

        // The expected SD hash value. (From the SD-JWT specification)
        String expected = "taqonN2gZHHzR8UbHqFf0oFN1kNmOW6AvV3AJxn3WNw";

        // The SD hash value computed by the SDJWT class implementation.
        String actual = sdJwt.getSDHash();

        // The SD hash values must match.
        assertEquals(expected, actual);
    }


    @Test
    public void test_hash_algorithm_not_specified()
    {
        // SD-JWT whose credential JWT does not contain the "_sd_alg" claim.
        SDJWT sdJwt = new SDJWT("a.b.c", List.of(new Disclosure("key", "value")));

        // When the "_sd_alg" claim is not available, the default algorithm
        // should be returned.
        assertEquals(SDConstants.DEFAULT_HASH_ALGORITHM, sdJwt.getHashAlgorithm());
    }


    @Test
    public void test_hash_algorithm_specified()
    {
        // A payload including the "_sd_alg" claim specifying an algorithm.
        byte[] payload = "{\"_sd_alg\":\"sha-512\"}".getBytes(StandardCharsets.UTF_8);

        // A dummy credential JWT.
        String crJwt = "header." + SDUtility.toBase64url(payload) + ".signature";

        // SD-JWT whose credential JWT contains the "_sd_alg" claim.
        SDJWT sdJwt = new SDJWT(crJwt, List.of(new Disclosure("key", "value")));

        // When the "_sd_ag" claim is available, the getHashAlgorithm() method
        // should return the value of the claim.
        assertEquals("sha-512", sdJwt.getHashAlgorithm());

        // The SD hash value should have been computed using the hash algorithm
        // specified by the "_sd_alg" claim.
        String sdHash = SDUtility.computeDigest("sha-512", sdJwt.toString());
        assertEquals(sdHash, sdJwt.getSDHash());
    }
}
