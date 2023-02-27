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
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;


/**
 * The common super class for {@link SDIssuance} and {@link SDPresentation},
 * which represent the "Combined Format for Issuance" and the "Combined Format
 * for Presentation" defined in the SD-JWT specification, respectively.
 *
 * <p>
 * Instances of this class (and the subclasses) are immutable. References to
 * {@link Disclosure} instances given to the constructor are internally copied
 * and the {@link #getDisclosures()} method returns the copied list as an
 * unmodifiable list.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/"
 *      >Selective Disclosure for JWTs (SD-JWT)</a>
 *
 * @since 1.0
 */
public abstract class SDCombinedFormat
{
    final String DELIMITER = "~";


    private final String sdJwt;
    private final List<Disclosure> disclosures;


    /**
     * Constructor with an SD-JWT and disclosures.
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
     * @throws IllegalArgumentException
     *         The given SD-JWT is null.
     */
    protected SDCombinedFormat(String sdJwt, Collection<Disclosure> disclosures)
    {
        // If an SD-JWT is not given.
        if (sdJwt == null)
        {
            throw new IllegalArgumentException("'sdJwt' is missing.");
        }

        // SD-JWT
        this.sdJwt = sdJwt;

        // Disclosures
        this.disclosures = (disclosures == null)
                ? Collections.unmodifiableList(Collections.emptyList())
                : disclosures.stream()
                    .filter(Objects::nonNull)
                    .collect(Collectors.toUnmodifiableList());
    }


    /**
     * Get the SD-JWT.
     *
     * @return
     *         The SD-JWT.
     */
    public String getSDJwt()
    {
        return sdJwt;
    }


    /**
     * Get the list of disclosures.
     *
     * @return
     *         The list of disclosures. The returned list is always non-null
     *         and unmodifiable.
     */
    public List<Disclosure> getDisclosures()
    {
        return disclosures;
    }


    /**
     * Check whether this instance is an instance of {@link SDIssuance} that
     * represents the "Combined Format for Issuance".
     *
     * <p>
     * When this method returns {@code true}, this instance can be cast to
     * {@link SDIssuance}.
     * </p>
     *
     * @return
     *         {@code true} if this instance is an instance of
     *         {@link SDIssuance}.
     */
    public boolean isIssuance()
    {
        return (this instanceof SDIssuance);
    }


    /**
     * Check whether this instance is an instance of {@link SDPresentation}
     * that represents the "Combined Format for Presentation".
     *
     * <p>
     * When this method returns {@code true}, this instance can be cast to
     * {@link SDPresentation}.
     * </p>
     *
     * @return
     *         {@code true} if this instance is an instance of
     *         {@link SDPresentation}.
     */
    public boolean isPresentation()
    {
        return (this instanceof SDPresentation);
    }


    /**
     * Get the string representation of this Combined Format.
     *
     * <blockquote>
     * <dl>
     *
     * <dt>Case 1: Combined Format for Issuance</dt>
     * <dd>
     * <i>{SD-JWT}</i>{@code ~}<i>{Disclosure-1}</i>{@code ~}...{@code ~}<i>{Disclosure-N}</i>
     * </dd>
     *
     * <dt>Case 2: Combined Format for Presentation with no Binding JWT</dt>
     * <dd>
     * <i>{SD-JWT}</i>{@code ~}<i>{Disclosure-1}</i>{@code ~}...{@code ~}<i>{Disclosure-M}</i>{@code ~}
     * </dd>
     *
     * <dt>Case 3: Combined Format for Presentation with a Binding JWT</dt>
     * <dd>
     * <i>{SD-JWT}</i>{@code ~}<i>{Disclosure-1}</i>{@code ~}...{@code ~}<i>{Disclosure-M}</i>{@code ~}<i>{Binding-JWT}</i>
     * </dd>
     *
     * </dl>
     * </blockquote>
     *
     * @return
     *         The string representation of this Combined Format.
     */
    @Override
    public String toString()
    {
        return serialize();
    }


    abstract String serialize();


    /**
     * Parse the given string as a "Combined Format".
     *
     * <p>
     * When the given string has been parsed successfully, this method returns
     * an instance of either {@link SDIssuance} or {@link SDPresentation}.
     * </p>
     *
     * @param input
     *         A "Combined Format". When null is given, null is returned.
     *
     * @return
     *         An instance of either {@link SDIssuance} or {@link SDPresentation}
     *         created as a result of parsing the input string.
     *
     * @throws IllegalArgumentException
     *         The given string is malformed.
     */
    public static SDCombinedFormat parse(String input)
    {
        return SDCombinedFormatParser.parse(input);
    }
}
