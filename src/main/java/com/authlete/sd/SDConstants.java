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


import java.util.Collections;
import java.util.Set;


/**
 * Constants used by this SD-JWT library implementation.
 */
final class SDConstants
{
    /**
     * The default hash algorithm ("sha-256").
     *
     * @see <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg"
     *      >IANA: Named Information Hash Algorithm Registry</a>
     */
    public static final String DEFAULT_HASH_ALGORITHM = "sha-256";


    /**
     * The "{@code _sd}" key reserved by the SD-JWT specification.
     */
    public static final String KEY_SD = "_sd";


    /**
     * The "{@code _sd_alg}" key reserved by the SD-JWT specification.
     */
    public static final String KEY_SD_ALG = "_sd_alg";


    /**
     * The "{@code _sd_jwt}" key reserved by the SD-JWT specification.
     */
    public static final String KEY_SD_JWT = "_sd_jwt";


    /**
     * The "{@code ...}" key reserved by the SD-JWT specification.
     */
    public static final String KEY_THREE_DOTS = "...";


    /**
     * Keys reserved by the SD-JWT specification.
     */
    public static final Set<String> RESERVED_KEYS =
            Collections.unmodifiableSet(
                    Set.of(KEY_SD, KEY_SD_ALG, KEY_SD_JWT, KEY_THREE_DOTS));


    /**
     * Claims that are not selectively-disclosable.
     */
    public static final Set<String> RETAINED_CLAIMS =
            Collections.unmodifiableSet(
                    Set.of("iss", "iat", "nbf", "exp", "cnf", "type", "status"));
}
