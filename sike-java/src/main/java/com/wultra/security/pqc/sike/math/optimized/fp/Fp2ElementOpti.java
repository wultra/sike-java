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

import com.wultra.security.pqc.sike.math.api.Fp2Element;
import com.wultra.security.pqc.sike.math.api.FpElement;
import com.wultra.security.pqc.sike.param.SikeParam;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Element of a quadratic extension field F(p^2): x0 + x1*i.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Fp2ElementOpti implements Fp2Element {

    private final FpElement x0;
    private final FpElement x1;

    private final SikeParam sikeParam;
    private final FpMath fpMath;

    /**
     * The F(p^2) field element constructor for given F(p) elements.
     * @param sikeParam SIKE parameters.
     * @param x0 The x0 real F(p) element.
     * @param x1 The x1 imaginary F(p) element.
     */
    public Fp2ElementOpti(SikeParam sikeParam, FpElement x0, FpElement x1) {
        this.sikeParam = sikeParam;
        this.fpMath = new FpMath(sikeParam);
        this.x0 = x0.copy();
        this.x1 = x1.copy();
    }

    /**
     * The F(p^2) field element constructor for given BigInteger values.
     * @param sikeParam SIKE parameters.
     * @param x0b The x0 real F(p) element.
     * @param x1b The x1 imaginary F(p) element.
     */
    public Fp2ElementOpti(SikeParam sikeParam, BigInteger x0b, BigInteger x1b) {
        this.sikeParam = sikeParam;
        this.fpMath = new FpMath(sikeParam);
        this.x0 = new FpElementOpti(sikeParam, x0b);
        this.x1 = new FpElementOpti(sikeParam, x1b);
    }

    /**
     * Construct the zero element 0 + 0*i.
     * @param sikeParam SIKE parameters.
     * @return Zero element.
     */
    public static Fp2ElementOpti zero(SikeParam sikeParam) {
        return new Fp2ElementOpti(sikeParam, BigInteger.ZERO, BigInteger.ZERO);
    }

    /**
     * Construct the one element 1 + 0*i.
     * @param sikeParam SIKE parameters.
     * @return One element.
     */
    public static Fp2ElementOpti one(SikeParam sikeParam) {
        return new Fp2ElementOpti(sikeParam, BigInteger.ONE, BigInteger.ZERO);
    }

    /**
     * Generate an element with value x0i + 0*i.
     * @param sikeParam SIKE parameters.
     * @param x0i Integer value for the real part of element.
     * @return Generated element.
     */
    public static Fp2ElementOpti generate(SikeParam sikeParam, BigInteger x0i) {
        return new Fp2ElementOpti(sikeParam, x0i, BigInteger.ZERO);
    }

    /**
     * Get the real part of element.
     * @return Real part of element.
     */
    public FpElement getX0() {
        return x0;
    }

    /**
     * Get the imaginary part of element.
     * @return Imaginary part of element.
     */
    public FpElement getX1() {
        return x1;
    }

    /**
     * Add two elements.
     * @param y Other element.
     * @return Calculation result.
     */
    public Fp2Element add(Fp2Element y) {
        // y = (x0 + i*x1) + (y0 + i*y1) = x0 + y0 + i*(x1 + y1)
        FpElementOpti r, i;

        r = fpMath.fpAddRdc((FpElementOpti) x0, (FpElementOpti) y.getX0());
        i = fpMath.fpAddRdc((FpElementOpti) x1, (FpElementOpti) y.getX1());
        return new Fp2ElementOpti(sikeParam, r, i);
    }

    /**
     * Subtract two elements.
     * @param y Other element.
     * @return Calculation result.
     */
    public Fp2Element subtract(Fp2Element y) {
        // y = (x0 + i*x1) - (y0 + i*y1) = x0 - y0 + i*(x1 - y1)
        FpElementOpti r, i;

        r = fpMath.fpSubRdc((FpElementOpti) x0, (FpElementOpti) y.getX0());
        i = fpMath.fpSubRdc((FpElementOpti) x1, (FpElementOpti) y.getX1());
        return new Fp2ElementOpti(sikeParam, r, i);
    }

    /**
     * Multiply two elements.
     * @param y Other element.
     * @return Calculation result.
     */
    public Fp2Element multiply(Fp2Element y) {
        FpElementOpti a = (FpElementOpti) x0;
        FpElementOpti b = (FpElementOpti) x1;
        FpElementOpti c = (FpElementOpti) y.getX0();
        FpElementOpti d = (FpElementOpti) y.getX1();

        // (a + bi) * (c + di) = (a * c - b * d) + (a * d + b * c)i

        FpElementOpti ac = fpMath.fpMul(a, c);
        FpElementOpti bd = fpMath.fpMul(b, d);

        FpElementOpti bMinusA = fpMath.fpSubRdc(b, a);
        FpElementOpti cMinusD = fpMath.fpSubRdc(c, d);

        FpElementOpti adPlusBC = fpMath.fpMul(bMinusA, cMinusD);
        adPlusBC = fpMath.fp2Add(adPlusBC, ac);
        adPlusBC = fpMath.fp2Add(adPlusBC, bd);

        // x1 = (a * d + b * c) * R mod p
        FpElementOpti x1o = fpMath.fpMontRdc(adPlusBC);

        FpElementOpti acMinusBd = fpMath.fp2Sub(ac, bd);
        FpElementOpti x0o = fpMath.fpMontRdc(acMinusBd);

        // x0 = (a * c - b * d) * R mod p
        return new Fp2ElementOpti(sikeParam, x0o, x1o);
    }

    @Override
    public Fp2Element multiplyByI() {
        return new Fp2ElementOpti(sikeParam, x1.negate(), x0.copy());
    }

    /**
     * Square the element.
     * @return Calculation result.
     */
    public Fp2ElementOpti square() {
        FpElementOpti a = (FpElementOpti) x0;
        FpElementOpti b = (FpElementOpti) x1;

        // (a + bi) * (a + bi) = (a^2 - b^2) + (2ab)i.
        FpElementOpti a2 = fpMath.fpAddRdc(a, a);
        FpElementOpti aPlusB = fpMath.fpAddRdc(a, b);
        FpElementOpti aMinusB = fpMath.fpSubRdc(a, b);
        FpElementOpti a2MinB2 = fpMath.fpMul(aPlusB, aMinusB);
        FpElementOpti ab2 = fpMath.fpMul(a2, b);

        // (a^2 - b^2) * R mod p
        FpElementOpti x0o = fpMath.fpMontRdc(a2MinB2);

        // 2 * a * b * R mod p
        FpElementOpti x1o = fpMath.fpMontRdc(ab2);

        return new Fp2ElementOpti(sikeParam, x0o, x1o);
    }

    @Override
    public Fp2Element pow(BigInteger n) {
        throw new IllegalStateException("Not implemented yet");
    }

    /**
     * Calculate the square root of the element.
     * @return Calculation result.
     */
    public Fp2ElementOpti sqrt() {
        throw new IllegalStateException("Not implemented yet");
    }

    /**
     * Invert the element.
     * @return Calculation result.
     */
    public Fp2ElementOpti inverse() {
        FpElementOpti e1 = fpMath.fpMul((FpElementOpti) x0, (FpElementOpti) x0);
        FpElementOpti e2 = fpMath.fpMul((FpElementOpti) x1, (FpElementOpti) x1);
        e1 = fpMath.fp2Add(e1, e2);
        // (a^2 + b^2) * R mod p
        FpElementOpti f1 = fpMath.fpMontRdc(e1);

        FpElementOpti f2 = fpMath.fpMulRdc(f1, f1);
        f2 = p34(f2);
        f2 = fpMath.fpMulRdc(f2, f2);
        f2 = fpMath.fpMulRdc(f2, f1);

        e1 = fpMath.fpMul((FpElementOpti) x0, f2);
        FpElementOpti x0o = fpMath.fpMontRdc(e1);

        f1 = fpMath.fpSubRdc(new FpElementOpti(sikeParam), (FpElementOpti) x1);
        e1 = fpMath.fpMul(f1, f2);
        FpElementOpti x1o = fpMath.fpMontRdc(e1);

        return new Fp2ElementOpti(sikeParam, x0o, x1o);
    }

    @Override
    public Fp2Element negate() {
        return new Fp2ElementOpti(sikeParam, x1.negate(), x0.copy());
    }

    /**
     * Compute x ^ ((p - 3) / 4).
     * @param x Value x.
     * @return Computed value.
     */
    private FpElementOpti p34(FpElementOpti x) {
        FpElementOpti[] lookup = new FpElementOpti[16];
        int[] powStrategy = sikeParam.getPowStrategy();
        int[] mulStrategy = sikeParam.getMulStrategy();
        int initialMul = sikeParam.getInitialMul();
        FpElementOpti xx = fpMath.fpMulRdc(x, x);
        lookup[0] = x.copy();
        for (int i = 1; i < 16; i++) {
            lookup[i] = fpMath.fpMulRdc(lookup[i - 1], xx);
        }
        FpElementOpti dest = lookup[initialMul];
        for (int i = 0; i < powStrategy.length; i++) {
            dest = fpMath.fpMulRdc(dest, dest);
            for (int j = 1; j < powStrategy[i]; j++) {
                dest = fpMath.fpMulRdc(dest, dest);
            }
            dest = fpMath.fpMulRdc(dest, lookup[mulStrategy[i]]);
        }
        return dest;
    }

    @Override
    public boolean isZero() {
        return x0.isZero() && x1.isZero();
    }

    /**
     * Copy the element.
     * @return Element copy.
     */
    public Fp2ElementOpti copy() {
        return new Fp2ElementOpti(sikeParam, x0.copy(), x1.copy());
    }

    /**
     * Encode the element in bytes.
     * @return Encoded element in bytes.
     */
    public byte[] getEncoded() {
        byte[] x0Encoded = x0.getEncoded();
        byte[] x1Encoded = x1.getEncoded();
        byte[] encoded = new byte[x0Encoded.length + x1Encoded.length];
        System.arraycopy(x0Encoded, 0, encoded, 0, x0Encoded.length);
        System.arraycopy(x1Encoded, 0, encoded, x0Encoded.length, x1Encoded.length);
        return encoded;
    }

    /**
     * Convert element to octet string.
     * @return Octet string.
     */
    public String toOctetString() {
        return x0.toOctetString() + x1.toOctetString();
    }

    @Override
    public String toString() {
        return x1.getX() + "i" + " + " + x0.getX();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Fp2ElementOpti that = (Fp2ElementOpti) o;
        return sikeParam.equals(that.sikeParam)
                && x0.equals(that.x0)
                && x1.equals(that.x1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sikeParam, x0, x1);
    }
}
