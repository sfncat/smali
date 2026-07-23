/*
 * Copyright 2024, Google LLC
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

package com.android.tools.smali.dexlib2.cli;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.raw.HeaderItem;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * A small diagnostic CLI that inspects the raw DEX header layout of a single dex file
 * and reports whether the file is a real DEX v41 container or a "pseudo v41" file
 * (magic claims v41 but header_size is still 0x70, as produced by some vendor
 * toolchains, e.g. Huawei/HOS).
 *
 * Usage:
 *   java -cp dexlib2.jar com.android.tools.smali.dexlib2.cli.DexHeaderInspect <dex-file>
 */
public class DexHeaderInspect {

    private static final int LEGACY_HEADER_SIZE    = 0x70;
    private static final int CONTAINER_HEADER_SIZE = 0x78;

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("Usage: DexHeaderInspect <path-to.dex>");
            System.exit(2);
        }

        byte[] buf = Files.readAllBytes(Paths.get(args[0]));
        System.out.printf("File          : %s%n", args[0]);
        System.out.printf("File size     : %d bytes (0x%x)%n", buf.length, buf.length);

        if (buf.length < 0x70) {
            System.out.println("ERROR: file is too short to be a dex header");
            System.exit(1);
        }

        // ----- magic / version -----
        StringBuilder magic = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            byte b = buf[i];
            if (b >= 0x20 && b < 0x7f) {
                magic.append((char) b);
            } else {
                magic.append(String.format("\\x%02x", b & 0xff));
            }
        }
        System.out.printf("Magic         : \"%s\" (raw: %s)%n", magic, hex(buf, 0, 8));

        int dexVersion = HeaderItem.getVersion(buf, 0);
        System.out.printf("Dex version   : %d%n", dexVersion);

        // ----- header fields -----
        int fileSizeField  = readU32(buf, HeaderItem.FILE_SIZE_OFFSET);
        int headerSize     = readU32(buf, HeaderItem.HEADER_SIZE_OFFSET);
        int endianTag      = readU32(buf, HeaderItem.ENDIAN_TAG_OFFSET);
        int mapOff         = readU32(buf, HeaderItem.MAP_OFFSET);
        int stringIdsSize  = readU32(buf, HeaderItem.STRING_COUNT_OFFSET);
        int stringIdsOff   = readU32(buf, HeaderItem.STRING_START_OFFSET);

        System.out.printf("file_size     : %d (0x%x)%n", fileSizeField, fileSizeField);
        System.out.printf("header_size   : %d (0x%x)  [legacy=0x70, container=0x78]%n",
                headerSize, headerSize);
        System.out.printf("endian_tag    : 0x%08x%n", endianTag);
        System.out.printf("map_off       : 0x%x%n", mapOff);
        System.out.printf("string_ids    : size=%d, off=0x%x%n", stringIdsSize, stringIdsOff);

        // ----- v41 container fields -----
        int containerSizeField = readU32(buf, HeaderItem.CONTAINER_SIZE_OFFSET);
        int containerOffField  = readU32(buf, HeaderItem.HEADER_OFFSET_OFFSET);
        System.out.printf("bytes@0x70    : 0x%08x  (would be container_size for real v41)%n",
                containerSizeField);
        System.out.printf("bytes@0x74    : 0x%08x  (would be container_off  for real v41)%n",
                containerOffField);

        // ----- pseudo / real classification -----
        boolean magicIsV41Plus = dexVersion >= 41;
        boolean realContainer = magicIsV41Plus && headerSize >= CONTAINER_HEADER_SIZE;
        boolean pseudoV41 = magicIsV41Plus && headerSize == LEGACY_HEADER_SIZE;

        System.out.println();
        System.out.println("=== Classification ===");
        if (!magicIsV41Plus) {
            System.out.println("  -> Legacy dex (version < 41). No container fields expected.");
        } else if (realContainer) {
            System.out.println("  -> Real DEX v41 CONTAINER format (header_size >= 0x78).");
            System.out.printf("     container_off should equal this header offset (0 here): %s%n",
                    containerOffField == 0 ? "OK" : "MISMATCH(0x" + Integer.toHexString(containerOffField) + ")");
        } else if (pseudoV41) {
            System.out.println("  -> PSEUDO v41 dex: magic=041 but header_size=0x70.");
            System.out.println("     The bytes at 0x70/0x74 are NOT container fields.");
            System.out.printf("     They are part of string_ids[]: at 0x%x..0x%x.%n",
                    stringIdsOff, stringIdsOff + stringIdsSize * 4 - 1);
            if (stringIdsOff <= LEGACY_HEADER_SIZE && stringIdsOff + stringIdsSize * 4 > LEGACY_HEADER_SIZE) {
                int idx = (LEGACY_HEADER_SIZE - stringIdsOff) / 4;
                System.out.printf("     => byte@0x70 corresponds to string_ids[%d] = 0x%08x%n",
                        idx,     readU32(buf, stringIdsOff + idx * 4));
                System.out.printf("     => byte@0x74 corresponds to string_ids[%d] = 0x%08x%n",
                        idx + 1, readU32(buf, stringIdsOff + (idx + 1) * 4));
            }
        } else {
            System.out.printf("  -> Unusual layout: version=%d, header_size=0x%x.%n",
                    dexVersion, headerSize);
        }

        // ----- try parsing with current dexlib2 code path -----
        System.out.println();
        System.out.println("=== Probe: DexBackedDexFile constructor with current dexlib2 ===");
        boolean parseOk = false;
        boolean reportedContainer = false;
        try {
            DexBackedDexFile dex = new DexBackedDexFile(null, buf);
            reportedContainer = dex.isContainer();
            System.out.printf("  parse OK: classes=%d, fileSize()=%d, isContainer()=%s%n",
                    dex.getClasses().size(), dex.getFileSize(), reportedContainer);
            parseOk = true;
        } catch (RuntimeException ex) {
            System.out.printf("  parse FAILED: %s: %s%n",
                    ex.getClass().getName(), ex.getMessage());
        }

        // ----- simulate ZipDexContainer multi-dex loop -----
        System.out.println();
        System.out.println("=== Probe: simulate ZipDexContainer multi-dex loop ===");
        simulateZipDexContainerLoop(buf);

        System.out.println();
        System.out.println("=== Conclusion ===");
        if (pseudoV41) {
            if (parseOk && !reportedContainer) {
                System.out.println("  PSEUDO v41 detected (magic=041, header_size=0x70).");
                System.out.println("  dexlib2 correctly treated it as a single legacy-layout dex");
                System.out.println("  (isContainer()==false). The fix gating the v41 branch on");
                System.out.println("  `header_size >= 0x78` is in effect.");
            } else if (parseOk) {
                System.out.println("  PSEUDO v41 detected, but dexlib2 reported isContainer()=true.");
                System.out.println("  This is unexpected and indicates the gating logic is not active.");
            } else {
                System.out.println("  PSEUDO v41 detected. Current dexlib2 forces the v41 branch in");
                System.out.println("  DexBackedDexFile based ONLY on the magic, then reads bytes at");
                System.out.println("  offset 0x74 expecting `container_off`, but those bytes actually");
                System.out.println("  belong to string_ids[]. The non-zero value mismatches");
                System.out.println("  header_offset (0) and triggers \"Unexpected container offset\".");
                System.out.println("  Fix direction: gate the v41 branch on `header_size >= 0x78`.");
            }
        } else if (realContainer) {
            System.out.println("  Real DEX v41 container.");
            if (parseOk) {
                System.out.printf("  dexlib2 parse OK, isContainer()=%s.%n", reportedContainer);
            } else {
                System.out.println("  dexlib2 parse FAILED; container layout may be malformed.");
            }
        } else {
            System.out.println("  Legacy dex (version < 41).");
        }
    }

    private static void simulateZipDexContainerLoop(byte[] buf) {
        Constructor<DexBackedDexFile> ctor;
        try {
            ctor = DexBackedDexFile.class.getDeclaredConstructor(
                    Opcodes.class, byte[].class, int.class, boolean.class, int.class);
            ctor.setAccessible(true);
        } catch (NoSuchMethodException e) {
            System.out.println("  cannot reflect 5-arg DexBackedDexFile ctor: " + e);
            return;
        }

        int offset = 0;
        int i = 1;
        while (offset < buf.length) {
            System.out.printf("  iteration %d: header_offset=0x%x%n", i, offset);
            try {
                DexBackedDexFile dex = ctor.newInstance(
                        /* opcodes= */ null, buf, /* offset= */ 0,
                        /* verifyMagic= */ true, /* header_offset= */ offset);
                int sz = dex.getFileSize();
                System.out.printf("    parsed sub-dex, getFileSize()=%d (0x%x)%n", sz, sz);
                offset += sz;
                if (sz <= 0) {
                    System.out.println("    abort: non-positive fileSize, would loop forever");
                    break;
                }
            } catch (InvocationTargetException ex) {
                Throwable cause = ex.getCause();
                System.out.printf("    THROW: %s: %s%n",
                        cause.getClass().getSimpleName(), cause.getMessage());
                break;
            } catch (ReflectiveOperationException ex) {
                System.out.println("    reflection error: " + ex);
                break;
            }
            i++;
            if (i > 16) {
                System.out.println("    abort: too many iterations");
                break;
            }
        }
    }

    private static int readU32(byte[] buf, int off) {
        return  (buf[off]     & 0xff)
             | ((buf[off + 1] & 0xff) << 8)
             | ((buf[off + 2] & 0xff) << 16)
             | ((buf[off + 3] & 0xff) << 24);
    }

    private static String hex(byte[] buf, int off, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", buf[off + i] & 0xff));
        }
        return sb.toString();
    }
}
