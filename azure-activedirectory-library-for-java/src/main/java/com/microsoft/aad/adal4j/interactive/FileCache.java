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

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.io.ByteStreams;

import java.io.*;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public class FileCache {
    private String cacheBasePath;
    private Map<String, FileSource> fileSources;

    private static final String ETAG_FILE_NAME = "ad-interactive-auth_etag.txt";

    LoadingCache<String, File> fileCache = CacheBuilder.newBuilder()
            .maximumSize(50)
            .build(new FileCacheLoader());

    public FileCache(FileSource[] sources) {
        // default cache base path to temp folder
        cacheBasePath = System.getProperty("java.io.tmpdir");

        // initialize file sources
        fileSources = new HashMap<String, FileSource>(sources.length);
        for(FileSource source : sources) {
            fileSources.put(source.getFileName(), source);
        }
    }

    public String getCacheBasePath() {
        return cacheBasePath;
    }

    public void setCacheBasePath(String cacheBasePath) {
        this.cacheBasePath = cacheBasePath;
    }

    public File getFile(String fileName) throws ExecutionException {
        if (!fileSources.containsKey(fileName)) {
            return null;
        }

        return fileCache.get(fileName);
    }

    private class FileCacheLoader extends CacheLoader<String, File> {
        @Override
        public File load(String key) throws Exception {
            FileSource source = fileSources.get(key);
            File file = new File(cacheBasePath, source.getFileName());

            // load the current etag value if we already have a copy of the
            // jar cached locally
            File etagFile = new File(cacheBasePath, ETAG_FILE_NAME);
            String etag = null;
            if(etagFile.exists() && file.exists()) {
                FileInputStream is = new FileInputStream(etagFile);
                BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                etag = reader.readLine();
                reader.close();
            }

            HttpURLConnection connection = (HttpURLConnection)source.getUrl().openConnection();

            // if we have an etag cached then send that in the "If-None-Match" header
            if(etag != null) {
                connection.setRequestProperty("If-None-Match", etag);
            }

            int statusCode = connection.getResponseCode();
            // if HTTP status is equal to 304 then our cached copy is still good to use
            if(statusCode == HttpURLConnection.HTTP_NOT_MODIFIED) {
                return file;
            }

            // if HTTP status is not 200 then we bail
            if(statusCode != HttpURLConnection.HTTP_OK) {
                // TODO: Is IOException the right exception type to raise?
                throw new IOException("File cache: server URL returned HTTP status code " +
                        Integer.toString(statusCode));
            }

            // download and save the file
            file.createNewFile();
            FileOutputStream output = new FileOutputStream(file);
            InputStream input = connection.getInputStream();
            ByteStreams.copy(input, output);
            input.close();
            output.close();

            // save the etag to file
            String newEtag = connection.getHeaderField("ETag");
            etagFile.createNewFile();
            output = new FileOutputStream(etagFile);
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(output));
            writer.write(newEtag);
            writer.close();
            output.close();

            return file;
        }
    }
}
