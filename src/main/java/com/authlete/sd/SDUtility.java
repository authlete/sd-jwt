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


import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import com.google.gson.Gson;


/**
 * Utility used by this SD-JWT library implementation.
 */
final class SDUtility
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Gson GSON = new Gson();


    /**
     * Base64url-decode the input.
     */
    public static byte[] fromBase64url(String input)
    {
        return Base64.getUrlDecoder().decode(input);
    }


    /**
     * Base64url-encode the input.
     */
    public static String toBase64url(byte[] input)
    {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }


    /**
     * Convert the input (JSON) to an instance of the specified class.
     */
    public static <T> T fromJson(String input, Class<T> klass)
    {
        return GSON.fromJson(input, klass);
    }


    /**
     * Convert the input object to JSON.
     */
    public static String toJson(Object input)
    {
        return GSON.toJson(input);
    }


    /**
     * Create a String instance from a UTF-8 byte sequence.
     *
     * @throws IllegalArgumentException
     *         A malformed-input or unmappable-character error was detected.
     */
    public static String fromUTF8Bytes(byte[] input)
    {
        ByteBuffer byteBuffer  = ByteBuffer.wrap(input);
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();

        try
        {
            return decoder.decode(byteBuffer).toString();
        }
        catch (CharacterCodingException cause)
        {
            // A malformed-input or unmappable-character error
            throw new IllegalArgumentException(
                    "Invalid UTF-8 byte sequence.", cause);
        }
    }


    /**
     * Convert the input string to a UTF-8 byte sequence.
     */
    public static byte[] toUTF8Bytes(String input)
    {
        return input.getBytes(StandardCharsets.UTF_8);
    }


    /**
     * Compute the digest of the input with the specified hash algorithm.
     *
     * @throws IllegalArgumentException
     *         The specified hash algorithm is not supported.
     */
    public static byte[] computeDigest(String hashAlgorithm, byte[] input)
    {
        try
        {
            return MessageDigest.getInstance(hashAlgorithm).digest(input);
        }
        catch (NoSuchAlgorithmException cause)
        {
            // Error message
            String message = String.format(
                    "The hash algorithm '%s' is not supported.", hashAlgorithm);

            throw new IllegalArgumentException(message, cause);
        }
    }


    /**
     * Compute the digest of the input with the specified hash algorithm.
     *
     * <p>
     * The digest computation is conducted on the UTF-8 byte sequence
     * representation of the input string.
     * </p>
     *
     * @return
     *         A base64url-encoded digest value.
     *
     * @throws IllegalArgumentException
     *         The specified hash algorithm is not supported.
     */
    public static String computeDigest(String hashAlgorithm, String input)
    {
        byte[] digest = computeDigest(hashAlgorithm, toUTF8Bytes(input));

        return toBase64url(digest);
    }


    /**
     * Generate a byte array of the specified size containing a random value.
     */
    public static byte[] generateRandomBytes(int size)
    {
        byte[] bytes = new byte[size];

        RANDOM.nextBytes(bytes);

        return bytes;
    }


    /**
     * Generate a random digest value.
     */
    public static String generateRandomDigest(String hashAlgorithm)
    {
        // Random value with 512-bit entropy.
        byte[] input  = generateRandomBytes(64);
        byte[] digest = computeDigest(hashAlgorithm, input);

        return toBase64url(digest);
    }


    /**
     * Check whether the given key is reserved by the SD-JWT specification.
     */
    public static boolean isReservedKey(String key)
    {
        return SDConstants.RESERVED_KEYS.contains(key);
    }


    /**
     * Create a decoy array element.
     */
    public static Map<String, Object> generateDecoyArrayElement(String hashAlgorithm)
    {
        String digest = generateRandomDigest(hashAlgorithm);

        // { "...": "<digest>" }
        return Map.of(SDConstants.KEY_THREE_DOTS, digest);
    }
}
