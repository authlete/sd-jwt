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


import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * A class that represents the "Combined Format for Presentation" defined in
 * the SD-JWT specification.
 *
 * <p>
 * Instances of this class are immutable.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/"
 *      >Selective Disclosure for JWTs (SD-JWT)</a>
 *
 * @since 1.0
 */
public class SDPresentation extends SDCombinedFormat
{
    private final String serialized;
    private final String bindingJwt;


    /**
     * Constructor with an SD-JWT and disclosures.
     *
     * <p>
     * This constructor is an alias of {@link #SDPresentation(String, Collection, String)
     * SDPresentation}{@code (sdJwt, disclosures, null)}.
     * </p>
     *
     * @param sdJwt
     *         An SD-JWT. Must not be null.
     *
     * @param disclosures
     *         Disclosures. May be null.
     *
     * @throws IllegalArgumentException
     *         The given SD-JWT is null.
     */
    public SDPresentation(String sdJwt, Collection<Disclosure> disclosures)
    {
        this(sdJwt, disclosures, null);
    }


    /**
     * Constructor with an SD-JWT, disclosures and a binding JWT.
     *
     * <p>
     * The references to {@link Disclosure} instances in the given disclosure
     * collection are internally copied and the {@link #getDisclosures()}
     * method returns the copied list as an unmodifiable list. On copy, null
     * elements in the given collection are filtered out.
     * </p>
     *
     * @param sdJwt
     *         An SD-JWT. Must not be null.
     *
     * @param disclosures
     *         Disclosures. May be null.
     *
     * @param bindingJwt
     *         A binding JWT. May be null.
     *
     * @throws IllegalArgumentException
     *         The given SD-JWT is null.
     */
    public SDPresentation(
            String sdJwt, Collection<Disclosure> disclosures, String bindingJwt)
    {
        super(sdJwt, disclosures);

        // SD-JWT, Disclosure1, Disclosure2, ..., DisclosureM
        Stream<String> stream = Stream.concat(
                Stream.of(sdJwt),
                getDisclosures().stream().map(Disclosure::getDisclosure));

        // SD-JWT, Disclosure1, Disclosure2, ..., DisclosureM, Binding-JWT
        stream = Stream.concat(
                stream,
                Stream.of(bindingJwt != null ? bindingJwt : ""));

        // Build a string representation of this Combined Format and cache it.
        this.serialized = stream.collect(Collectors.joining(DELIMITER));

        // Binding JWT
        this.bindingJwt = bindingJwt;
    }


    /**
     * Get the binding JWT.
     *
     * @return
     *         The binding JWT.
     */
    public String getBindingJwt()
    {
        return bindingJwt;
    }


    @Override
    String serialize()
    {
        return serialized;
    }
}
