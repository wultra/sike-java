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
package com.wultra.security.pqc.sike.model;

import com.wultra.security.pqc.sike.math.FpElement;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.util.ByteEncoding;
import com.wultra.security.pqc.sike.util.OctetEncoding;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Objects;

/**
 * SIDH or SIKE private key.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SidhPrivateKey implements PrivateKey {

    private final SikeParam sikeParam;
    private final FpElement key;
    private byte[] s;

    /**
     * Construct private key from a number.
     * @param sikeParam SIKE parameters.
     * @param secret Secret value of the private key.
     */
    public SidhPrivateKey(SikeParam sikeParam, BigInteger secret) {
        this.sikeParam = sikeParam;
        this.key = new FpElement(sikeParam.getPrime(), secret);
        // TODO - verify the private key
    }

    /**
     * Construct private key from bytes.
     * @param sikeParam SIKE parameters.
     * @param bytes Byte value of the private key.
     */
    public SidhPrivateKey(SikeParam sikeParam, byte[] bytes) {
        this(sikeParam, ByteEncoding.fromByteArray(bytes));
    }


    /**
     * Construct private key from bytes with specified parameter s for SIKE decapsulation.
     * @param sikeParam SIKE parameters.
     * @param key Byte value of the private key.
     * @param s Parameter s for SIKE decapsulation
     */
    public SidhPrivateKey(SikeParam sikeParam, BigInteger key, byte[] s) {
        this(sikeParam, key);
        this.s = s;
    }

    // TODO add constructor with official octet format from SIKE specification

    /**
     * Get the private key as an F(p) element.
     * @return Private key as an F(p) element.
     */
    public FpElement getKey() {
        return key;
    }

    /**
     * Get the private key as a number.
     * @return Private key as a number.
     */
    public BigInteger getM() {
        return key.getX();
    }

    /**
     * Get parameter s for decapsulation.
     * @return Parameter s for decapsulation.
     */
    public byte[] getS() {
        return s;
    }

    @Override
    public String getAlgorithm() {
        return sikeParam.getName();
    }

    @Override
    public String getFormat() {
        // ASN.1 encoding is not supported
        return null;
    }

    /**
     * Get the private key encoded as bytes.
     * @return Private key encoded as bytes.
     */
    public byte[] getEncoded() {
        return key.getEncoded();
    }

    /**
     * Convert private key into an octet string.
     * @return Octet string.
     */
    public String toOctetString() {
        String prefix = "";
        if (s != null) {
            prefix = OctetEncoding.toOctetString(s, 16);
        }
        return prefix + OctetEncoding.toOctetString(key.getX(), (sikeParam.getMsbA() + 7) / 8);
    }

    @Override
    public String toString() {
        return key.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SidhPrivateKey that = (SidhPrivateKey) o;
        return sikeParam.equals(that.sikeParam) &&
                key.equals(that.key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sikeParam, key);
    }
}
