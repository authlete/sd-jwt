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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;


public final class SDCombinedFormatTest
{
    private static SDCombinedFormat parse(String input)
    {
        return SDCombinedFormat.parse(input);
    }


    @Test
    public void test_01_issuance_sdjwt_only()
    {
        String sdJwt = "a.b.c";

        // Issuance with no disclosures.
        String input = sdJwt;

        // Parse the input.
        SDCombinedFormat cf = parse(input);

        // Type
        assertTrue( cf.isIssuance());
        assertFalse(cf.isPresentation());
        assertTrue( cf instanceof SDIssuance);

        // SD-JWT
        assertEquals(sdJwt, cf.getSDJwt());

        // Disclosures
        assertEquals(0, cf.getDisclosures().size());
    }


    @Test
    public void test_02_issuance_1_disclosure()
    {
        String sdJwt = "a.b.c";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";

        // Issuance with 1 disclosure.
        String input = String.format("%s~%s", sdJwt, dc0);

        // Parse the input.
        SDCombinedFormat cf = parse(input);

        // Type
        assertTrue( cf.isIssuance());
        assertFalse(cf.isPresentation());
        assertTrue( cf instanceof SDIssuance);

        // SD-JWT
        assertEquals(sdJwt, cf.getSDJwt());

        // Disclosures
        assertEquals(1, cf.getDisclosures().size());

        Disclosure disclosure0 = cf.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());
    }


    @Test
    public void test_03_issuance_2_disclosures()
    {
        String sdJwt = "a.b.c";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";
        String dc1   = "WyJXcEtIQmVTa3A5U2MyNVV4a1F1RmNRIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0";

        // Issuance with 2 disclosures.
        String input = String.format("%s~%s~%s", sdJwt, dc0, dc1);

        // Parse the input.
        SDCombinedFormat cf = parse(input);

        // Type
        assertTrue( cf.isIssuance());
        assertFalse(cf.isPresentation());
        assertTrue( cf instanceof SDIssuance);

        // SD-JWT
        assertEquals(sdJwt, cf.getSDJwt());

        // Disclosures
        assertEquals(2, cf.getDisclosures().size());

        Disclosure disclosure0 = cf.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());

        Disclosure disclosure1 = cf.getDisclosures().get(1);
        assertEquals(dc1, disclosure1.getDisclosure());
    }


    @Test
    public void test_04_presentation_sdjwt_only()
    {
        String sdJwt = "a.b.c";

        // Presentation with no disclosures and no binding JWT.
        String input = sdJwt + "~";

        // Parse the input.
        SDCombinedFormat cf = parse(input);

        // Type
        assertFalse(cf.isIssuance());
        assertTrue( cf.isPresentation());
        assertTrue( cf instanceof SDPresentation);

        // SD-JWT
        assertEquals(sdJwt, cf.getSDJwt());

        // Disclosures
        assertEquals(0, cf.getDisclosures().size());

        // Binding JWT
        SDPresentation presentation = (SDPresentation)cf;
        assertNull(presentation.getBindingJwt());
    }


    @Test
    public void test_05_presentation_1_disclosure()
    {
        String sdJwt = "a.b.c";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";

        // Presentation with 1 disclosure and no binding JWT.
        String input = String.format("%s~%s~", sdJwt, dc0);

        // Parse the input.
        SDCombinedFormat cf = parse(input);

        // Type
        assertFalse(cf.isIssuance());
        assertTrue( cf.isPresentation());
        assertTrue( cf instanceof SDPresentation);

        // SD-JWT
        assertEquals(sdJwt, cf.getSDJwt());

        // Disclosures
        assertEquals(1, cf.getDisclosures().size());

        Disclosure disclosure0 = cf.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());

        // Binding JWT
        SDPresentation presentation = (SDPresentation)cf;
        assertNull(presentation.getBindingJwt());
    }


    @Test
    public void test_06_presentation_2_disclosures()
    {
        String sdJwt = "a.b.c";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";
        String dc1   = "WyJXcEtIQmVTa3A5U2MyNVV4a1F1RmNRIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0";

        // Presentation with 2 disclosures and no binding JWT.
        String input = String.format("%s~%s~%s~", sdJwt, dc0, dc1);

        // Parse the input.
        SDCombinedFormat cf = parse(input);

        // Type
        assertFalse(cf.isIssuance());
        assertTrue( cf.isPresentation());
        assertTrue( cf instanceof SDPresentation);

        // SD-JWT
        assertEquals(sdJwt, cf.getSDJwt());

        // Disclosures
        assertEquals(2, cf.getDisclosures().size());

        Disclosure disclosure0 = cf.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());

        Disclosure disclosure1 = cf.getDisclosures().get(1);
        assertEquals(dc1, disclosure1.getDisclosure());

        // Binding JWT
        SDPresentation presentation = (SDPresentation)cf;
        assertNull(presentation.getBindingJwt());
    }


    @Test
    public void test_07_presentation_sdjwt_bdjwt()
    {
        String sdJwt = "a.b.c";
        String bdJwt = "d.e.f";

        // Presentation with no disclosures and a binding JWT.
        String input = String.format("%s~%s", sdJwt, bdJwt);

        // Parse the input.
        SDCombinedFormat cf = parse(input);

        // Type
        assertFalse(cf.isIssuance());
        assertTrue( cf.isPresentation());
        assertTrue( cf instanceof SDPresentation);

        // SD-JWT
        assertEquals(sdJwt, cf.getSDJwt());

        // Disclosures
        assertEquals(0, cf.getDisclosures().size());

        // Binding JWT
        SDPresentation presentation = (SDPresentation)cf;
        assertEquals(bdJwt, presentation.getBindingJwt());
    }


    @Test
    public void test_08_presentation_1_disclosure_bdjwt()
    {
        String sdJwt = "a.b.c";
        String bdJwt = "d.e.f";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";

        // Presentation with 1 disclosure and a binding JWT.
        String input = String.format("%s~%s~%s", sdJwt, dc0, bdJwt);

        // Parse the input.
        SDCombinedFormat cf = parse(input);

        // Type
        assertFalse(cf.isIssuance());
        assertTrue( cf.isPresentation());
        assertTrue( cf instanceof SDPresentation);

        // SD-JWT
        assertEquals(sdJwt, cf.getSDJwt());

        // Disclosures
        assertEquals(1, cf.getDisclosures().size());

        Disclosure disclosure0 = cf.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());

        // Binding JWT
        SDPresentation presentation = (SDPresentation)cf;
        assertEquals(bdJwt, presentation.getBindingJwt());
    }


    @Test
    public void test_09_presentation_2_disclosures_bdjwt()
    {
        String sdJwt = "a.b.c";
        String bdJwt = "d.e.f";
        String dc0   = "WyI0d3dqUzlyMm4tblBxdzNpTHR0TkFBIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd";
        String dc1   = "WyJXcEtIQmVTa3A5U2MyNVV4a1F1RmNRIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0";

        // Presentation with 2 disclosures and a binding JWT.
        String input = String.format("%s~%s~%s~%s", sdJwt, dc0, dc1, bdJwt);

        // Parse the input.
        SDCombinedFormat cf = parse(input);

        // Type
        assertFalse(cf.isIssuance());
        assertTrue( cf.isPresentation());
        assertTrue( cf instanceof SDPresentation);

        // SD-JWT
        assertEquals(sdJwt, cf.getSDJwt());

        // Disclosures
        assertEquals(2, cf.getDisclosures().size());

        Disclosure disclosure0 = cf.getDisclosures().get(0);
        assertEquals(dc0, disclosure0.getDisclosure());

        Disclosure disclosure1 = cf.getDisclosures().get(1);
        assertEquals(dc1, disclosure1.getDisclosure());

        // Binding JWT
        SDPresentation presentation = (SDPresentation)cf;
        assertEquals(bdJwt, presentation.getBindingJwt());
    }
}
