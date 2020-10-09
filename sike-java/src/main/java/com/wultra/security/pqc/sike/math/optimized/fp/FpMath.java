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

import com.wultra.security.pqc.sike.param.SikeParam;

/**
 * Field mathematics implementation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class FpMath {

    // TODO - merge with FpElementOpti

    private final SikeParam sikeParam;

    public FpMath(SikeParam sikeParam) {
        this.sikeParam = sikeParam;
    }

    /**
     * Compute z = x + y (mod 2*p).
     * @param x Value x for addition.
     * @param y Value y for addition.
     * @return Added value.
     */
    public FpElementOpti fpAddRdc(FpElementOpti x, FpElementOpti y) {
        FpElementOpti z = new FpElementOpti(sikeParam);
        long carry = 0L;

        // z = x + y % p
        for (int i = 0; i < sikeParam.getFpWords(); i++) {
            long[] result = UnsignedLong.add(x.getValue()[i], y.getValue()[i], carry);
            z.getValue()[i] = result[0];
            carry = result[1];
        }

        // z = z - p * 2
        carry = 0L;
        for (int i = 0; i < sikeParam.getFpWords(); i++) {
            long[] result = UnsignedLong.sub(z.getValue()[i], sikeParam.getPx2().getValue()[i], carry);
            z.getValue()[i] = result[0];
            carry = result[1];
        }

        // if z < 0, add p * 2 back
        long mask = -carry;
        carry = 0L;
        for (int i = 0; i < sikeParam.getFpWords(); i++) {
            long[] result = UnsignedLong.add(z.getValue()[i], sikeParam.getPx2().getValue()[i] & mask, carry);
            z.getValue()[i] = result[0];
            carry = result[1];
        }
        return z;
    }

    /**
     * Compute z = x - y (mod 2*p).
     * @param x Value x for subtraction.
     * @param y Value y for subtraction.
     * @return Subtracted value.
     */
    public FpElementOpti fpSubRdc(FpElementOpti x, FpElementOpti y) {
        FpElementOpti z = new FpElementOpti(sikeParam);
        long borrow = 0L;

        // z = z - p * 2
        for (int i = 0; i < sikeParam.getFpWords(); i++) {
            long[] result = UnsignedLong.sub(x.getValue()[i], y.getValue()[i], borrow);
            z.getValue()[i] = result[0];
            borrow = result[1];
        }

        // if z < 0, add p * 2 back
        long mask = -borrow;
        borrow = 0L;
        for (int i = 0; i < sikeParam.getFpWords(); i++) {
            long[] result = UnsignedLong.add(z.getValue()[i], sikeParam.getPx2().getValue()[i] & mask, borrow);
            z.getValue()[i] = result[0];
            borrow = result[1];
        }
        return z;
    }

    /**
     * Reduce a field element in [0, 2*p) to one in [0,p).
     * @param x Value x for reduction.
     */
    public void fpRdcP(FpElementOpti x) {
        long borrow = 0L;
        for (int i = 0; i < sikeParam.getFpWords(); i++) {
            long[] result = UnsignedLong.sub(x.getValue()[i], sikeParam.getP().getValue()[i], borrow);
            x.getValue()[i] = result[0];
            borrow = result[1];
        }

        // Sets all bits if borrow = 1
        long mask = -borrow;
        borrow = 0L;
        for (int i = 0; i < sikeParam.getFpWords(); i++) {
            long[] result = UnsignedLong.add(x.getValue()[i], sikeParam.getP().getValue()[i] & mask, borrow);
            x.getValue()[i] = result[0];
            borrow = result[1];
        }
    }

    /**
     * Swap field elements.
     * @param x First element.
     * @param y Second element.
     * @param mask Swap condition, if zero swap is not performed.
     */
    public void fpSwapCond(FpElementOpti x, FpElementOpti y, long mask) {
        if (mask != 0L) {
            FpElementOpti tmp = new FpElementOpti(sikeParam);
            System.arraycopy(y.getValue(), 0, tmp.getValue(), 0, sikeParam.getFpWords());
            System.arraycopy(x.getValue(), 0, y.getValue(), 0, sikeParam.getFpWords());
            System.arraycopy(tmp.getValue(), 0, x.getValue(), 0, sikeParam.getFpWords());
        }
    }

    /**
     * Compute z = x * y.
     * @param x Value x.
     * @param y Value y.
     * @return Multiplication result.
     */
    public FpElementOpti fpMul(FpElementOpti x, FpElementOpti y) {
        FpElementOpti z = new FpElementOpti(sikeParam, new long[sikeParam.getFpWords() * 2]);
        long carry;
        long t = 0L;
        long u = 0L;
        long v = 0L;

        for (int i = 0; i < sikeParam.getFpWords(); i++) {
            for (int j = 0; j <= i; j++) {
                long[] mulResult = UnsignedLong.mul(x.getValue()[j], y.getValue()[i - j]);
                long[] addResult1 = UnsignedLong.add(mulResult[1], v, 0L);
                v = addResult1[0];
                carry = addResult1[1];
                long[] addResult2 = UnsignedLong.add(mulResult[0], u, carry);
                u = addResult2[0];
                carry = addResult2[1];
                t = t + carry;
            }
            z.getValue()[i] = v;
            v = u;
            u = t;
            t = 0L;
        }

        for (int i = sikeParam.getFpWords(); i < (2 * sikeParam.getFpWords()) - 1; i++) {
            for (int j = i - sikeParam.getFpWords() + 1; j < sikeParam.getFpWords(); j++) {
                long[] mulResult = UnsignedLong.mul(x.getValue()[j], y.getValue()[i - j]);
                long[] addResult1 = UnsignedLong.add(mulResult[1], v, 0L);
                v = addResult1[0];
                carry = addResult1[1];
                long[] addResult2 = UnsignedLong.add(mulResult[0], u, carry);
                u = addResult2[0];
                carry = addResult2[1];
                t = t + carry;
            }
            z.getValue()[i] = v;
            v = u;
            u = t;
            t = 0L;
        }
        z.getValue()[2 * sikeParam.getFpWords() - 1] = v;
        return z;
    }

    /**
     * Perform Montgomery reduction. Destroys the input value.
     * @param x Input value.
     * @return Reduced value.
     */
    public FpElementOpti fpMontRdc(FpElementOpti x) {
        FpElementOpti z = new FpElementOpti(sikeParam, new long[sikeParam.getFpWords()]);
        long carry;
        long t = 0L;
        long u = 0L;
        long v = 0L;
        int count = sikeParam.getZeroWords(); // number of 0 digits in the least significant part of p + 1

        for (int i = 0; i < sikeParam.getFpWords(); i++) {
            for (int j = 0; j < i; j++) {
                if (j < i - count + 1) {
                    long[] mulResult = UnsignedLong.mul(z.getValue()[j], sikeParam.getP1().getValue()[i - j]);
                    long[] addResult1 = UnsignedLong.add(mulResult[1], v, 0L);
                    v = addResult1[0];
                    carry = addResult1[1];
                    long[] addResult2 = UnsignedLong.add(mulResult[0], u, carry);
                    u = addResult2[0];
                    carry = addResult2[1];
                    t = t + carry;
                }
            }
            long[] addResult1 = UnsignedLong.add(v, x.getValue()[i], 0L);
            v = addResult1[0];
            carry = addResult1[1];
            long[] addResult2 = UnsignedLong.add(u, 0L, carry);
            u = addResult2[0];
            carry = addResult2[1];
            t = t + carry;
            z.getValue()[i] = v;
            v = u;
            u = t;
            t = 0L;
        }

        for (int i = sikeParam.getFpWords(); i < (2 * sikeParam.getFpWords()) - 1; i++) {
            if (count > 0) {
                count--;
            }
            for (int j = i - sikeParam.getFpWords() + 1; j < sikeParam.getFpWords(); j++) {
                if (j < (sikeParam.getFpWords() - count)) {
                    long[] mulResult = UnsignedLong.mul(z.getValue()[j], sikeParam.getP1().getValue()[i - j]);
                    long[] addResult1 = UnsignedLong.add(mulResult[1], v, 0L);
                    v = addResult1[0];
                    carry = addResult1[1];
                    long[] addResult2 = UnsignedLong.add(mulResult[0], u, carry);
                    u = addResult2[0];
                    carry = addResult2[1];
                    t = t + carry;
                }
            }
            long[] addResult1 = UnsignedLong.add(v, x.getValue()[i], 0L);
            v = addResult1[0];
            carry = addResult1[1];
            long[] addResult2 = UnsignedLong.add(u, 0L, carry);
            u = addResult2[0];
            carry = addResult2[1];
            t = t + carry;
            z.getValue()[i - sikeParam.getFpWords()] = v;
            v = u;
            u = t;
            t = 0L;
        }
        long[] addResult = UnsignedLong.add(v, x.getValue()[2 * sikeParam.getFpWords() - 1], 0L);
        z.getValue()[sikeParam.getFpWords() - 1] = addResult[0];
        return z;
    }

    /**
     * Compute z = x + y, without reducing mod p.
     * @param x Value x.
     * @param y Value y.
     * @return Addition result.
     */
    public FpElementOpti fp2Add(FpElementOpti x, FpElementOpti y) {
        FpElementOpti z = new FpElementOpti(sikeParam, new long[sikeParam.getFpWords() * 2]);
        long carry = 0L;
        for (int i = 0; i < 2 * sikeParam.getFpWords(); i++) {
            long[] addResult = UnsignedLong.add(x.getValue()[i], y.getValue()[i], carry);
            z.getValue()[i] = addResult[0];
            carry = addResult[1];
        }
        return z;
    }

    /**
     * Compute z = x - y, without reducing mod p.
     * @param x Value x.
     * @param y Value y.
     * @return Subtraction result.
     */
    public FpElementOpti fp2Sub(FpElementOpti x, FpElementOpti y) {
        FpElementOpti z = new FpElementOpti(sikeParam, new long[sikeParam.getFpWords() * 2]);
        long borrow = 0L;

        for (int i = 0; i < sikeParam.getFpWords() * 2; i++) {
            long[] result = UnsignedLong.sub(x.getValue()[i], y.getValue()[i], borrow);
            z.getValue()[i] = result[0];
            borrow = result[1];
        }
        long mask = -borrow;
        borrow = 0L;
        for (int i = sikeParam.getFpWords(); i < sikeParam.getFpWords() * 2; i++) {
            long[] result = UnsignedLong.add(z.getValue()[i], sikeParam.getP().getValue()[i - sikeParam.getFpWords()] & mask, borrow);
            z.getValue()[i] = result[0];
            borrow = result[1];
        }
        return z;
    }

    /**
     * Montgomery multiplication. Input values must be already in Montgomery domain.
     * @param a Value a.
     * @param b Value b.
     * @return Multiplication result.
     */
    public FpElementOpti fpMulRdc(FpElementOpti a, FpElementOpti b) {
        FpElementOpti ab = fpMul(a, b);
        return fpMontRdc(ab);
    }

}
