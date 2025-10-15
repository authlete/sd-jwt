/*
 * Copyright (C) 2025 Authlete, Inc.
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


import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


class CollectionUtility
{
    @SuppressWarnings("unchecked")
    public static <E> List<E> listOf(E... elements)
    {
        List<E> list = new ArrayList<>(elements.length);

        for (E element : elements)
        {
            list.add(element);
        }

        return list;
    }


    @SuppressWarnings("unchecked")
    public static <E> Set<E> setOf(E... elements)
    {
        Set<E> set = new LinkedHashSet<>(elements.length);

        for (E element : elements)
        {
            set.add(element);
        }

        return set;
    }


    public static <K, V> Map<K, V> mapOf()
    {
        return new LinkedHashMap<>();
    }


    public static <K, V> Map<K, V> mapOf(K k1, V v1)
    {
        Map<K, V> map = new LinkedHashMap<>(1);

        map.put(k1, v1);

        return map;
    }


    public static <K, V> Map<K, V> mapOf(K k1, V v1, K k2, V v2)
    {
        Map<K, V> map = new LinkedHashMap<>(2);

        map.put(k1, v1);
        map.put(k2, v2);

        return map;
    }


    public static <K, V> Map<K, V> mapOf(K k1, V v1, K k2, V v2, K k3, V v3)
    {
        Map<K, V> map = new LinkedHashMap<>(3);

        map.put(k1, v1);
        map.put(k2, v2);
        map.put(k3, v3);

        return map;
    }
}
