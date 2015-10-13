/*******************************************************************************
 * Copyright © Microsoft Open Technologies, Inc.
 *
 * All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 * See the Apache License, Version 2.0 for the specific language
 * governing permissions and limitations under the License.
 ******************************************************************************/
package com.microsoft.aad.adal4j;

import java.util.Objects;

/**
 * Contains identifier for a user.
 */
public final class UserIdentifier {
    private static final String ANY_USER_ID = "AnyUser";
    /**
     * A static instance of {@link UserIdentifier} to represent any user.
     */
    public static final UserIdentifier ANY_USER = new UserIdentifier(ANY_USER_ID, UserIdentifierType.UNIQUE_ID);

    private final String id;
    private final UserIdentifierType type;

    public UserIdentifier(final String id, final UserIdentifierType type) {
        if (StringHelper.isBlank(id)) {
            throw new IllegalArgumentException("id is null or empty");
        }
        this.id = id;
        this.type = type;
    }

    /**
     * @return the type of the {@link UserIdentifier}.
     */
    public UserIdentifierType getType() {
        return this.type;
    }

    /**
     * @return id of the {@link UserIdentifier}.
     */
    public String getId() {
        return this.id;
    }

    boolean isAnyUser() {
        return this.type == ANY_USER.type && Objects.equals(this.id, ANY_USER.id);
    }

    String getUniqueId() {
        return (!this.isAnyUser() && this.type == UserIdentifierType.UNIQUE_ID) ? this.id : null;
    }

    String getDisplayableId() {
        return (!this.isAnyUser() && (this.type == UserIdentifierType.OPTIONAL_DISPLAYABLE_ID || this.type == UserIdentifierType.REQUIRED_DISPLAYABLE_ID)) ? this.id : null;
    }
}
