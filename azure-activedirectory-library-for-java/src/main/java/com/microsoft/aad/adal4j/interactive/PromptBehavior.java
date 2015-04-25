/**
 * Copyright 2014 Microsoft Open Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.microsoft.aad.adal4j.interactive;

public enum PromptBehavior {
    LOGIN("login"),
    REFRESH_SESSION("refresh_session"),

    // The behavior of this value is identical to prompt=none for managed users; However, for federated users, AAD
    // redirects to ADFS as it cannot determine in advance whether ADFS can login user silently (e.g. via WIA) or not.
    ATTEMPT_NONE("attempt_none");

    private final String name;

    private PromptBehavior(String name) {
        this.name = name;
    }

    public boolean equalsName(String otherName) {
        return otherName == null ? false : name.equals(otherName);
    }

    public String toString() {
        return name;
    }
}
