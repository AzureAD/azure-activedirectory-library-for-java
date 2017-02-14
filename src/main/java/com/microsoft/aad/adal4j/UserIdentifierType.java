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

/**
 * Indicates the type of {@link UserIdentifier}
 */
public enum UserIdentifierType {
    /**
     * When a {@link UserIdentifier} of this type is passed in a token acquisition operation,
     * the operation is guaranteed to return a token issued for the user with corresponding
     * {@link UserIdentifier#getUniqueId()} or fail.
     */
    UNIQUE_ID,

    /**
     * When a {@link UserIdentifier} of this type is passed in a token acquisition operation,
     * the operation restricts cache matches to the value provided and injects it as a hint in the
     * authentication experience. However the end user could overwrite that value, resulting in a token
     * issued to a different account than the one specified in the {@link UserIdentifier} in input.
     */
    OPTIONAL_DISPLAYABLE_ID,

    /**
     * When a {@link UserIdentifier} of this type is passed in a token acquisition operation,
     * the operation is guaranteed to return a token issued for the user with corresponding
     * {@link UserIdentifier#getDisplayableId()} (UPN or email) or fail
     */
    REQUIRED_DISPLAYABLE_ID,
    ;
}
