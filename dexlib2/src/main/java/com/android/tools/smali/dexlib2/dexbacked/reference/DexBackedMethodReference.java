/*
 * Copyright 2012, Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google LLC nor the names of its
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

package com.android.tools.smali.dexlib2.dexbacked.reference;

import com.android.tools.smali.dexlib2.base.reference.BaseMethodReference;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.raw.MethodIdItem;
import com.android.tools.smali.dexlib2.dexbacked.raw.ProtoIdItem;
import com.android.tools.smali.dexlib2.dexbacked.raw.TypeListItem;
import com.android.tools.smali.dexlib2.dexbacked.util.FixedSizeList;

import javax.annotation.Nonnull;

import java.util.Collections;
import java.util.List;

public class DexBackedMethodReference extends BaseMethodReference {
    @Nonnull public final DexBackedDexFile dexFile;
    private final int methodIndex;
    private int protoIdItemOffset;
    private boolean protoChecked;
    private boolean protoValid;

    private static final int MAX_PARAMETER_COUNT = 256;
    private static final String MALFORMED_TYPE = "Ljava/lang/Object;";

    public DexBackedMethodReference(@Nonnull DexBackedDexFile dexFile, int methodIndex) {
        this.dexFile = dexFile;
        this.methodIndex = methodIndex;
    }

    @Nonnull
    @Override
    public String getDefiningClass() {
        return dexFile.getTypeSection().get(dexFile.getBuffer().readUshort(
                dexFile.getMethodSection().getOffset(methodIndex) + MethodIdItem.CLASS_OFFSET));
    }

    @Nonnull
    @Override
    public String getName() {
        return dexFile.getStringSection().get(dexFile.getBuffer().readSmallUint(
                dexFile.getMethodSection().getOffset(methodIndex) + MethodIdItem.NAME_OFFSET));
    }

    private boolean ensureProtoValid() {
        if (protoChecked) {
            return protoValid;
        }
        protoChecked = true;
        try {
            getProtoIdItemOffset();
            protoValid = true;
        } catch (RuntimeException ex) {
            System.err.println("dexlib2: malformed method ref proto (methodIndex=" + methodIndex
                    + "): " + ex.getMessage());
            protoValid = false;
        }
        return protoValid;
    }

    @Nonnull
    @Override
    public List<String> getParameterTypes() {
        if (!ensureProtoValid()) {
            return Collections.emptyList();
        }
        final int parametersOffset = dexFile.getBuffer().readSmallUint(
                protoIdItemOffset + ProtoIdItem.PARAMETERS_OFFSET);
        if (parametersOffset > 0) {
            final int rawCount = dexFile.getDataBuffer().readSmallUint(
                    parametersOffset + TypeListItem.SIZE_OFFSET);
            if (rawCount < 0 || rawCount > MAX_PARAMETER_COUNT) {
                System.err.println("dexlib2: malformed method ref param count (methodIndex="
                        + methodIndex + ", parameterCount=" + rawCount + " > "
                        + MAX_PARAMETER_COUNT + "), treating as empty");
                return Collections.emptyList();
            }
            final int parameterCount = rawCount;
            final int paramListStart = parametersOffset + TypeListItem.LIST_OFFSET;
            return new FixedSizeList<String>() {
                @Nonnull
                @Override
                public String readItem(final int index) {
                    try {
                        return dexFile.getTypeSection().get(
                                dexFile.getDataBuffer().readUshort(paramListStart + 2*index));
                    } catch (RuntimeException ex) {
                        return MALFORMED_TYPE;
                    }
                }
                @Override public int size() { return parameterCount; }
            };
        }
        return Collections.emptyList();
    }

    @Nonnull
    @Override
    public String getReturnType() {
        if (!ensureProtoValid()) {
            return MALFORMED_TYPE;
        }
        try {
            return dexFile.getTypeSection().get(
                    dexFile.getBuffer().readSmallUint(protoIdItemOffset + ProtoIdItem.RETURN_TYPE_OFFSET));
        } catch (RuntimeException ex) {
            System.err.println("dexlib2: malformed method ref return type (methodIndex=" + methodIndex
                    + "): " + ex.getMessage());
            return MALFORMED_TYPE;
        }
    }

    private int getProtoIdItemOffset() {
        if (protoIdItemOffset == 0) {
            protoIdItemOffset = dexFile.getProtoSection().getOffset(dexFile.getBuffer().readUshort(
                    dexFile.getMethodSection().getOffset(methodIndex) + MethodIdItem.PROTO_OFFSET));
        }
        return protoIdItemOffset;
    }

    /**
     * Calculate and return the private size of a method reference.
     *
     * Calculated as: class_idx + proto_idx + name_idx
     *
     * @return size in bytes
     */
    public int getSize() {
        return MethodIdItem.ITEM_SIZE; //ushort + ushort + uint for indices
    }

    @Override
    public void validateReference() throws InvalidReferenceException {
        if (methodIndex < 0 || methodIndex >= dexFile.getMethodSection().size()) {
            throw new InvalidReferenceException("method@" + methodIndex);
        }
    }
}
