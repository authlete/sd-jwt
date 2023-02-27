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


import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;


/**
 * The implementation of {@link SDCombinedFormat#parse(String)}.
 */
final class SDCombinedFormatParser
{
    private static final String DELIMITER = "~";


    public static SDCombinedFormat parse(String input)
    {
        if (input == null)
        {
            return null;
        }

        // 1. Combined Format for Issuance
        //
        //     SD-JWT~Disclosure1~...~DisclosureN
        //
        // 2. Combined Format for Presentation with no binding JWT
        //
        //     SD-JWT~Disclosure1~...~DisclosureM~
        //
        // 3. Combined Format for Presentation with a binding JWT
        //
        //     SD-JWT~Disclosure1~...~DisclosureM~Binding-JWT
        //
        String[] elements = input.split(DELIMITER);

        if (elements.length == 0)
        {
            throw new IllegalArgumentException("The combined format is malformed.");
        }

        // The first element is an SD-JWT.
        String sdJwt = elements[0];

        // Whether the input string ends with "~". True when the input string
        // represents a Presentation with no binding JWT.
        boolean endsWithDelimiter = input.endsWith(DELIMITER);

        // A special case where the input string contains an SD-JWT only.
        if (elements.length == 1)
        {
            if (endsWithDelimiter)
            {
                // Presentation with no disclosures and no binding JWT.
                return new SDPresentation(sdJwt, null, null);
            }
            else
            {
                // Issuance with no disclosures.
                return new SDIssuance(sdJwt, null);
            }
        }

        // The number of elements is 2 or more.

        // The last element. It is either a disclosure or a binding JWT.
        String lastElement = elements[elements.length - 1];

        // Whether the last element seems a JWT (at least not a disclosure).
        // True when the input string represents a Presentation with a binding JWT.
        // (Also true when the last disclosure of the Presentation with no binding
        // JWT is badly formatted.)
        boolean endsWithJwt = 0 <= lastElement.indexOf('.');

        // Binding JWT (optional).
        String bindingJwt = (!endsWithDelimiter && endsWithJwt) ? lastElement : null;

        // The range of disclosures.
        int disclosureFromIndex = 1;
        int disclosureToIndex   = (bindingJwt != null) ? elements.length - 1 : elements.length;

        List<Disclosure> disclosures;

        try
        {
            disclosures = Arrays.asList(elements)
                    .subList(disclosureFromIndex, disclosureToIndex)
                    .stream()
                    .filter(element -> element.length() != 0)
                    .map(Disclosure::parse)
                    .collect(Collectors.toList());
        }
        catch (Exception cause)
        {
            throw new IllegalArgumentException("Failed to parse disclosures.", cause);
        }

        // If the input string represents a Presentation.
        if (endsWithDelimiter || bindingJwt != null)
        {
            // Presentation
            return new SDPresentation(sdJwt, disclosures, bindingJwt);
        }
        else
        {
            // Issuance
            return new SDIssuance(sdJwt, disclosures);
        }
    }
}
