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

import com.wultra.security.pqc.sike.util.ByteEncoding;
import com.wultra.security.pqc.sike.util.OctetEncoding;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Element of an F(p) field with a single coordinate x.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class FpElement {

    private final BigInteger x;

    private final BigInteger prime;

    /**
     * The F(p^) field element constructor for given integer value.
     * @param prime Field prime.
     * @param i Integer value.
     */
    public FpElement(BigInteger prime, int i) {
        this.prime = prime;
        this.x = new BigInteger(String.valueOf(i)).mod(prime);
    }

    /**
     * The F(p^) field element constructor for given BigInteger value.
     * @param prime Field prime.
     * @param x BigInteger value.
     */
    public FpElement(BigInteger prime, BigInteger x) {
        this.prime = prime;
        this.x = x.mod(prime);
    }

    /**
     * Get the element value.
     * @return the element value.
     */
    public BigInteger getX() {
        return x;
    }

    /**
     * Get the field prime.
     * @return Field prime.
     */
    public BigInteger getPrime() {
        return prime;
    }

    /**
     * Add two elements.
     * @param o Other element.
     * @return Calculation result.
     */
    public FpElement add(FpElement o) {
        return new FpElement(prime, x.add(o.x).mod(prime));
    }

    /**
     * Subtract two elements.
     * @param o Other element.
     * @return Calculation result.
     */
    public FpElement subtract(FpElement o) {
        return new FpElement(prime, x.subtract(o.x).mod(prime));
    }

    /**
     * Multiply two elements.
     * @param o Other element.
     * @return Calculation result.
     */
    public FpElement multiply(FpElement o) {
        return new FpElement(prime, x.multiply(o.x).mod(prime));
    }

    /**
     * Square the elements.
     * @return Calculation result.
     */
    public FpElement square() {
        return multiply(this);
    }

    /**
     * Invert the element.
     * @return Calculation result.
     */
    public FpElement inverse() {
        return new FpElement(prime, x.modInverse(prime));
    }

    /**
     * Negate the element.
     * @return Calculation result.
     */
    public FpElement negate() {
        return new FpElement(prime, prime.subtract(x));
    }

    /**
     * Get whether the element is the zero element.
     * @return Whether the element is the zero element.
     */
    public boolean isZero() {
        return BigInteger.ZERO.equals(x);
    }

    /**
     * Copy the element.
     * @return Element copy.
     */
    public FpElement copy() {
        return new FpElement(prime, x);
    }

    /**
     * Encode the element in bytes.
     * @return Encoded element in bytes.
     */
    public byte[] getEncoded() {
        int primeSize = (prime.bitLength() + 7) / 8;
        return ByteEncoding.toByteArray(x, primeSize);
    }

    /**
     * Convert element to octet string.
     * @return Octet string.
     */
    public String toOctetString() {
        int primeSize = (prime.bitLength() + 7) / 8;
        return OctetEncoding.toOctetString(x, primeSize);
    }

    @Override
    public String toString() {
        return x.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FpElement fpElement = (FpElement) o;
        return prime.equals(fpElement.prime)
                && x.equals(fpElement.x);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x);
    }
}
