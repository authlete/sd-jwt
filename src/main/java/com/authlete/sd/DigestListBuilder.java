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


import static com.authlete.sd.SDConstants.DEFAULT_HASH_ALGORITHM;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * A utility to build an "{@code _sd}" array that lists digest values.
 * This class is used in the implementation of {@link SDObjectBuilder}.
 */
final class DigestListBuilder
{
    private final String hashAlgorithm;
    private final Map<String, String> claimNameToDigestMap;
    private final Set<String> decoyDigestSet;


    /**
     * Constructor with the default hash algorithm ("{@code sha-256}").
     */
    public DigestListBuilder()
    {
        this(DEFAULT_HASH_ALGORITHM);
    }


    /**
     * Constructor with the specified hash algorithm.
     *
     * @param hashAlgorithm
     *         A hash algorithm. If {@code null} is given, the default hash
     *         algorithm ("{@code sha-256}") is used.
     */
    public DigestListBuilder(String hashAlgorithm)
    {
        this.hashAlgorithm = (hashAlgorithm != null)
                ? hashAlgorithm : DEFAULT_HASH_ALGORITHM;

        this.claimNameToDigestMap = new HashMap<>();
        this.decoyDigestSet       = new HashSet<>();
    }


    /**
     * Get the hash algorithm that has been specified by the constructor.
     *
     * @return
     *         The hash algorithm.
     */
    public String getHashAlgorithm()
    {
        return hashAlgorithm;
    }


    /**
     * Add the digest of the specified disclosure.
     *
     * <p>
     * If a disclosure having the same claim name has been added previously,
     * the previous digest value will be overwritten.
     * </p>
     *
     * @param disclosure
     *         A disclosure.
     *
     * @return
     *         The base64url-encoded digest value of the disclosure
     *         computed with the hash algorithm.
     */
    public String addDisclosureDigest(Disclosure disclosure)
    {
        String claimName = disclosure.getClaimName();
        String digest    = disclosure.digest(getHashAlgorithm());

        claimNameToDigestMap.put(claimName, digest);

        return digest;
    }


    /**
     * Add a decoy digest value.
     *
     * @return
     *         The base64url-encoded digest value of a randomly-generated
     *         value computed with the hash algorithm.
     */
    public String addDecoyDigest()
    {
        // Generate a random digest value.
        String digest = SDUtility.generateRandomDigest(getHashAlgorithm());

        decoyDigestSet.add(digest);

        return digest;
    }


    /**
     * Add decoy digest values.
     *
     * @param count
     *         The number of decoy digest values to add.
     *
     * @return
     *         A list of base64url-encoded digest values of randomly-generated
     *         values computed with the hash algorithm.
     */
    public List<String> addDecoyDigests(int count)
    {
        // A list of decoy digest values.
        List<String> digestList = new ArrayList<>();

        for (int i = 0; i < count; i++)
        {
            // Add one decoy digest value.
            String digest = addDecoyDigest();

            digestList.add(digest);
        }

        return digestList;
    }


    /**
     * Build an "{@code _sd}" array.
     *
     * <p>
     * Digest values in the returned list are sorted.
     * </p>
     */
    public List<String> build()
    {
        // Stream of disclosure digests and decoy digests.
        Stream<String> digests = Stream.concat(
                claimNameToDigestMap.values().stream(),
                decoyDigestSet.stream());

        // From the SD-JWT specification:
        //
        //   The Issuer MUST hide the original order of the claims in the array.
        //   To ensure this, it is RECOMMENDED to shuffle the array of hashes,
        //   e.g., by sorting it alphanumerically or randomly, after potentially
        //   adding decoy digests as described in Section 5.6. The precise
        //   method does not matter as long as it does not depend on the
        //   original order of elements.
        //
        return digests.sorted().collect(Collectors.toList());
    }


    String removeDigestByClaimName(String claimName)
    {
        return claimNameToDigestMap.remove(claimName);
    }
}
