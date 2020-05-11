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
package com.wultra.security.pqc.sike.math;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Element of a quadratic extension field F(p^2): x0 + x1*i.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Fp2Element {

    private final FpElement x0;
    private final FpElement x1;

    private final BigInteger prime;
    private final int primeSize;

    /**
     * The F(p^2) field element constructor for given F(p) elements.
     * @param prime Field prime.
     * @param x0 The x0 real F(p) element.
     * @param x1 The x1 imaginary F(p) element.
     */
    public Fp2Element(BigInteger prime, FpElement x0, FpElement x1) {
        this.prime = prime;
        this.primeSize = prime.bitLength() / 8 + 1;
        this.x0 = x0;
        this.x1 = x1;
    }

    /**
     * The F(p^2) field element constructor for given integer values.
     * @param prime Field prime.
     * @param x0i The x0 real integer value.
     * @param x1i The x1 imaginary integer value.
     */
    public Fp2Element(BigInteger prime, int x0i, int x1i) {
        this.prime = prime;
        this.primeSize = prime.bitLength() / 8 + 1;
        this.x0 = new FpElement(prime, x0i);
        this.x1 = new FpElement(prime, x1i);
    }

    /**
     * Construct the zero element 0 + 0*i.
     * @param prime Field prime.
     * @return Zero element.
     */
    public static Fp2Element zero(BigInteger prime) {
        return new Fp2Element(prime, 0, 0);
    }

    /**
     * Construct the one element 1 + 0*i.
     * @param prime Field prime.
     * @return One element.
     */
    public static Fp2Element one(BigInteger prime) {
        return new Fp2Element(prime, 1, 0);
    }

    /**
     * Generate an element with value x0i + 0*i.
     * @param prime Field prime.
     * @param x0i Integer value for the real part of element.
     * @return Generated element.
     */
    public static Fp2Element generate(BigInteger prime, int x0i) {
        return new Fp2Element(prime, x0i, 0);
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
        FpElement r, i;

        r = x0.add(y.getX0());
        i = x1.add(y.getX1());
        return new Fp2Element(prime, r, i);
    }

    /**
     * Subtract two elements.
     * @param y Other element.
     * @return Calculation result.
     */
    public Fp2Element subtract(Fp2Element y) {
        // y = (x0 + i*x1) - (y0 + i*y1) = x0 - y0 + i*(x1 - y1)
        FpElement r, i;

        r = x0.subtract(y.getX0());
        i = x1.subtract(y.getX1());
        return new Fp2Element(prime, r, i);
    }

    /**
     * Multiply two elements.
     * @param y Other element.
     * @return Calculation result.
     */
    public Fp2Element multiply(Fp2Element y) {
        // y = (x0 + i*x1) * (y0 + i*y1) = x0y0 - x1y1 + i*(x0y1 + x1y0)
        FpElement r1, r2, r, i1, i2, i;

        r1 = x0.multiply(y.getX0());
        r2 = x1.multiply(y.getX1());
        r = r1.subtract(r2);

        i1 = x0.multiply(y.getX1());
        i2 = x1.multiply(y.getX0());
        i = i1.add(i2);

        return new Fp2Element(prime, r, i);
    }

    /**
     * Multiply by the imaginary part of the element.
     * @return Calculation result.
     */
    public Fp2Element multiplyByI() {
        return new Fp2Element(prime, x1.negate(), x0.copy());
    }

    /**
     * Square the element.
     * @return Calculation result.
     */
    public Fp2Element square() {
        return multiply(this);
    }

    /**
     * Element exponentiation.
     * @param n Exponent
     * @return Calculation result.
     */
    public Fp2Element pow(BigInteger n) {
        if (n.compareTo(BigInteger.ZERO) < 0) {
            throw new ArithmeticException("Negative exponent");
        }
        if (n.compareTo(BigInteger.ZERO) == 0) {
            return Fp2Element.one(prime);
        }
        if (n.compareTo(BigInteger.ONE) == 0) {
            return copy();
        }
        BigInteger e = n;
        Fp2Element base = copy();
        Fp2Element result = Fp2Element.one(prime);
        while (e.compareTo(BigInteger.ZERO) > 0) {
            if (e.testBit(0)) {
                result = result.multiply(base);
            }
            e = e.shiftRight(1);
            base = base.square();
        }
        return result;
    }

    /**
     * Calculate the square root of the element.
     * @return Calculation result.
     */
    public Fp2Element sqrt() {
        // TODO - compare performance with reference C implementation, consider replacing algorithm
        if (isZero()) {
            return Fp2Element.zero(prime);
        }
        if (!isQuadraticResidue()) {
            throw new ArithmeticException("The square root of a quadratic non-residue cannot be computed");
        }
        if (prime.mod(new BigInteger("4")).compareTo(new BigInteger("3")) != 0) {
            throw new ArithmeticException("Field prime mod 4 is not 3");
        }
        Fp2Element a1, a2;
        Fp2Element neg1 = Fp2Element.one(prime);
        BigInteger p = prime;
        p = p.shiftRight(2);
        a1 = copy();
        a1 = a1.pow(p);
        a2 = copy();
        a2 = a2.multiply(a1);
        a1 = a1.multiply(a2);
        if (a1.equals(neg1)) {
            return a2.multiplyByI();
        }
        p = prime;
        p = p.shiftRight(1);
        a1 = a1.add(Fp2Element.one(prime));
        a1 = a1.pow(p);
        return a1.multiply(a2);
    }

    /**
     * Get whether the element is a quadratic residue modulo prime.
     * @return Whether the element is a quadratic residue.
     */
    public boolean isQuadraticResidue() {
        Fp2Element base = copy();
        BigInteger p = prime;
        p = p.multiply(p);
        p = p.subtract(BigInteger.ONE);
        p = p.shiftRight(1);
        base = base.pow(p);
        return base.equals(Fp2Element.one(prime));
    }

    /**
     * Invert the element.
     * @return Calculation result.
     */
    public Fp2Element inverse() {
        FpElement t0, t1, o0, o1;
        t0 = x0.square();
        t1 = x1.square();
        t0 = t0.add(t1);
        t0 = t0.inverse();
        o1 = x1.negate();
        o0 = x0.multiply(t0);
        o1 = o1.multiply(t0);
        return new Fp2Element(prime, o0, o1);
    }

    /**
     * Negate the element.
     * @return Calculation result.
     */
    public Fp2Element negate() {
        return new Fp2Element(prime, x0.negate(), x1.negate());
    }

    /**
     * Get whether the element is the zero element.
     * @return Whether the element is the zero element.
     */
    public boolean isZero() {
        return x0.isZero() && x1.isZero();
    }

    /**
     * Copy the element.
     * @return Element copy.
     */
    public Fp2Element copy() {
        return new Fp2Element(prime, new FpElement(prime, x0.getX()), new FpElement(prime, x1.getX()));
    }

    /**
     * Encode the element in bytes.
     * @return Encoded element in bytes.
     */
    public byte[] getEncoded() {
        byte[] encoded = new byte[primeSize * 2];
        byte[] x0Encoded = x0.getEncoded();
        byte[] x1Encoded = x1.getEncoded();
        System.arraycopy(x0Encoded, 0, encoded, 0, primeSize);
        System.arraycopy(x1Encoded, 0, encoded, primeSize, primeSize);
        return encoded;
    }

    @Override
    public String toString() {
        return x1 + "i" + " + " + x0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Fp2Element that = (Fp2Element) o;
        return x0.equals(that.x0) &&
                x1.equals(that.x1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x0, x1);
    }
}
