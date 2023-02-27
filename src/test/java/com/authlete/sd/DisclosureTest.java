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
import org.junit.Test;


public final class DisclosureTest
{
    @Test
    public void test_01_constructor()
    {
        // The following values are from the SD-JWT specification.
        String salt       = "_26bc4LT-ac6q2KI6cBW5es";
        String claimName  = "family_name";
        Object claimValue = "Möbius";

        // The expected disclosure here is the version of "No white space".
        //
        // (The implementation of Disclosure does not insert redundant
        // white spaces when it builds JSON internally.)
        String expectedDisclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd";

        Disclosure disclosure   = new Disclosure(salt, claimName, claimValue);
        String actualDisclosure = disclosure.getDisclosure();

        assertEquals(expectedDisclosure, actualDisclosure);
    }


    @Test
    public void test_02_parse()
    {
        // The following values are from the SD-JWT specification.
        // The input string is the version of "With white spaces".
        String input      = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
        String salt       = "_26bc4LT-ac6q2KI6cBW5es";
        String claimName  = "family_name";
        Object claimValue = "Möbius";

        // Parse the disclosure.
        Disclosure disclosure = Disclosure.parse(input);

        assertEquals(salt,       disclosure.getSalt());
        assertEquals(claimName,  disclosure.getClaimName());
        assertEquals(claimValue, disclosure.getClaimValue());
        assertEquals(input,      disclosure.getDisclosure());
    }
}
