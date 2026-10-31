/*
 * Copyright (C) 2026 Authlete, Inc.
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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


final class DigestDisclosureMap extends LinkedHashMap<String, Disclosure>
{
    private static final long serialVersionUID = 1L;


    /**
     * Tracker for referenced digests.
     */
    private final Set<String> referencedDigests = new HashSet<>();


    public static DigestDisclosureMap create(
            String hashAlgorithm, Collection<Disclosure> disclosures)
    {
        // Mappings from a disclosure digest to a disclosure.
        DigestDisclosureMap map = new DigestDisclosureMap();

        if (disclosures == null)
        {
            // Return an empty map.
            return map;
        }

        // For each disclosure.
        for (Disclosure disclosure : disclosures)
        {
            if (disclosure == null)
            {
                // Ignore.
                continue;
            }

            // Compute the digest of the disclosure with the hash algorithm.
            // The digest is used as a key.
            String key = disclosure.digest(hashAlgorithm);

            // Add a mapping from the disclosure digest to the disclosure.
            map.put(key, disclosure);
        }

        // Mappings from a disclosure digest to a disclosure.
        return map;
    }


    public Disclosure reference(String digest)
    {
        if (digest == null)
        {
            return null;
        }

        // RFC 9901, Section 7.1 (4)
        //
        //   If any digest value is encountered more than once in the
        //   Issuer-signed JWT payload (directly or recursively via other
        //   Disclosures), the SD-JWT MUST be rejected.

        // If the specified has already been referenced.
        if (referencedDigests.contains(digest))
        {
            throw new IllegalArgumentException(String.format(
                    "The digest '%s' was referenced more than once " +
                    "(RFC 9901, Section 7.1 (4)).", digest));
        }

        // Remember that the digest was referenced.
        referencedDigests.add(digest);

        // Get the disclosure corresponding to the digest.
        return get(digest);
    }


    public List<Disclosure> getUnreferencedDisclosures()
    {
        // The keys are the digests computed with the hash algorithm given
        // to create(), so compare them, not the default-algorithm digests.
        return entrySet().stream()
                .filter(entry -> !referencedDigests.contains(entry.getKey()))
                .map(Map.Entry::getValue)
                .collect(Collectors.toList());
    }
}
