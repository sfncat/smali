/*
 * Copyright 2016, Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 * Neither the name of Google LLC nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.android.tools.smali.smali;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class SmaliOptions {
    public int apiLevel = 15;
    public String outputDexFile = "out.dex";

    public int jobs = Runtime.getRuntime().availableProcessors();
    public boolean allowOdexOpcodes = false;
    public boolean verboseErrors = false;
    public boolean printTokens = false;

    /**
     * If true, continue processing other files even when some files fail to assemble.
     * Failed files will be skipped and errors will be reported.
     */
    public boolean continueOnError = false;

    /**
     * List of path patterns to exclude from assembly.
     * Files matching any of these patterns will be skipped.
     * Pattern format: substring match on file path (e.g., "com/alibaba/fastjson2")
     */
    public List<String> excludePatterns = new ArrayList<>();

    /**
     * Compiled exclude patterns for efficient matching.
     */
    private List<Pattern> compiledExcludePatterns = null;

    /**
     * Check if a file path should be excluded based on exclude patterns.
     * @param filePath the file path to check
     * @return true if the file should be excluded
     */
    public boolean shouldExclude(String filePath) {
        if (excludePatterns.isEmpty()) {
            return false;
        }
        // Normalize path separators
        String normalizedPath = filePath.replace('\\', '/');
        for (String pattern : excludePatterns) {
            if (normalizedPath.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
}
