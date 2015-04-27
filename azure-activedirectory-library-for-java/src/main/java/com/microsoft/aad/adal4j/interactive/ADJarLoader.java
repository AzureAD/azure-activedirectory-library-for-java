/**
 * Copyright 2014 Microsoft Open Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.microsoft.aad.adal4j.interactive;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.ExecutionException;

public class ADJarLoader {
    private static final String BASE_URL = "https://github.com/avranju/azure-activedirectory-library-for-java/blob/interactive/adal-ad-interactive-auth/dist/";
    private static FileCache filesCache;
    private static String jarName;

    static {
        String osName = System.getProperty("os.name").toLowerCase();
        boolean isWindows = osName.contains("win");
        boolean isMac = osName.contains("mac");
        boolean isLinux = osName.contains("linux");
        boolean isx64 = System.getProperty("os.arch").contains("64");

        // this name should finally look something like this:
        //  adal-ad-interactive-auth-0.1.0-win32-x64.jar?raw=true
        // TODO: The version number is embedded in the string constant
        // below. Is there a way for us to read this from the jar's manifest
        // instead?
        jarName = "adal-ad-interactive-auth-0.1.0-" +
                (isWindows ? "win32-" :
                    isMac ? "osx-" :
                    isLinux ? "linux-" : "") +
                (isx64 ? "x64" : "x86") +
                ".jar";
    }

    public static File load() throws ExecutionException, MalformedURLException {
        if(filesCache == null) {
            filesCache = new FileCache(new FileSource[] {
                new FileSource(jarName, new URL(BASE_URL + jarName + "?raw=true"))
            });
        }

        return filesCache.getFile(jarName);
    }
}
