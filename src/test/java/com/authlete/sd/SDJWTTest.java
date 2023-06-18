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
import static org.junit.Assert.assertNull;
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
}
