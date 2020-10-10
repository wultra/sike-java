/*
 * Copyright 2020 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.wultra.security.pqc.sike.math.optimized.fp;

import com.wultra.security.pqc.sike.math.api.FpElement;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.util.ByteEncoding;
import com.wultra.security.pqc.sike.util.OctetEncoding;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Representation of an optimized element of the base field F(p).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class FpElementOpti implements FpElement {

    private final SikeParam sikeParam;
    private final long[] value;
    private final FpMath fpMath;

    public FpElementOpti(SikeParam sikeParam) {
        long[] value = new long[sikeParam.getFpWords()];
        this.sikeParam = sikeParam;
        this.fpMath = new FpMath(sikeParam);
        this.value = value;
    }

    public FpElementOpti(SikeParam sikeParam, long[] value) {
        this.sikeParam = sikeParam;
        this.fpMath = new FpMath(sikeParam);
        this.value = value;
    }

    public FpElementOpti(SikeParam sikeParam, BigInteger x) {
        this.sikeParam = sikeParam;
        this.fpMath = new FpMath(sikeParam);
        // Convert element to Montgomery domain
        long[] value = new long[sikeParam.getFpWords()];
        int primeSize = (sikeParam.getPrime().bitLength() + 7) / 8;
        byte[] encoded = ByteEncoding.toByteArray(x, primeSize);
        for (int i = 0; i < primeSize; i++) {
            int j = i / 8;
            int k = i % 8;
            value[j] |= (Byte.toUnsignedLong(encoded[i]) << (8 * k));
        }
        FpElementOpti a = new FpElementOpti(sikeParam, value);
        FpElementOpti b = fpMath.fpMul(a, sikeParam.getPR2());
        FpElementOpti reduced = fpMath.fpMontRdc(b);
        this.value = new long[sikeParam.getFpWords()];
        System.arraycopy(reduced.getValue(), 0, this.value, 0, sikeParam.getFpWords());
    }

    public long[] getValue() {
        return value;
    }

    public int size() {
        return value.length;
    }

    @Override
    public BigInteger getX() {
        return ByteEncoding.fromByteArray(getEncoded());
    }

    @Override
    public FpElement add(FpElement o) {
        throw new IllegalStateException("Not implemented yet");
    }

    @Override
    public FpElement subtract(FpElement o) {
        throw new IllegalStateException("Not implemented yet");
    }

    @Override
    public FpElement multiply(FpElement o) {
        throw new IllegalStateException("Not implemented yet");
    }

    @Override
    public FpElement square() {
        throw new IllegalStateException("Not implemented yet");
    }

    @Override
    public FpElement inverse() {
        throw new IllegalStateException("Not implemented yet");
    }

    @Override
    public FpElement negate() {
        throw new IllegalStateException("Not implemented yet");
    }

    @Override
    public boolean isZero() {
        return Arrays.equals(new long[value.length], value);
    }

    public FpElementOpti copy() {
        return new FpElementOpti(sikeParam, value.clone());
    }

    @Override
    public byte[] getEncoded() {
        int primeSize = (sikeParam.getPrime().bitLength() + 7) / 8;
        byte[] bytes = new byte[primeSize];
        // Convert element from Montgomery domain
        long[] val = new long[sikeParam.getFpWords() * 2];
        System.arraycopy(value, 0, val, 0, sikeParam.getFpWords());
        FpElementOpti el = new FpElementOpti(sikeParam, val);
        FpElementOpti a = fpMath.fpMontRdc(el);
        fpMath.fpRdcP(a);
        for (int i = 0; i < primeSize; i++) {
            int j = i / 8;
            int k = i % 8;
            bytes[i] = (byte) (a.getValue()[j] >>> (8 * k));
        }
        return bytes;
    }

    @Override
    public String toOctetString() {
        int primeSize = (sikeParam.getPrime().bitLength() + 7) / 8;
        BigInteger x = ByteEncoding.fromByteArray(getEncoded());
        return OctetEncoding.toOctetString(x, primeSize);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof FpElementOpti)) {
            return false;
        }
        FpElementOpti other = (FpElementOpti) o;
        return getX().equals(other.getX());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length; i++) {
            sb.append(Long.toUnsignedString(value[i]));
            if (i < value.length - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }
}
