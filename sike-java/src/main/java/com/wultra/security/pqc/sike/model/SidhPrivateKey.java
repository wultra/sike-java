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

import com.wultra.security.pqc.sike.math.api.FpElement;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.util.ByteEncoding;
import com.wultra.security.pqc.sike.util.OctetEncoding;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * SIDH or SIKE private key.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SidhPrivateKey implements PrivateKey {

    private final SikeParam sikeParam;
    private final Party party;
    private final byte[] key;
    private byte[] s;

    /**
     * Construct private key from a number.
     * @param sikeParam SIKE parameters.
     * @param party Alice or Bob.
     * @param secret Secret value of the private key.
     */
    public SidhPrivateKey(SikeParam sikeParam, Party party, BigInteger secret) {
        this.sikeParam = sikeParam;
        this.party = party;
        validatePrivateKey(secret);
        int keyLength = (sikeParam.getPrime().bitLength() + 7) / 8;
        this.key = ByteEncoding.toByteArray(secret, keyLength);
        this.s = new byte[sikeParam.getMessageBytes()];
    }

    /**
     * Construct private key from bytes.
     * @param sikeParam SIKE parameters.
     * @param party Alice or Bob.
     * @param bytes Byte value of the private key.
     */
    public SidhPrivateKey(SikeParam sikeParam, Party party, byte[] bytes) {
        this.sikeParam = sikeParam;
        this.party = party;
        int sLength = sikeParam.getMessageBytes();
        int keyLength = (sikeParam.getPrime().bitLength() + 7) / 8;
        if (bytes == null || bytes.length != sLength + keyLength) {
            throw new InvalidParameterException("Invalid private key");
        }
        byte[] s = new byte[sLength];
        key = new byte[keyLength];
        System.arraycopy(bytes, 0, s, 0, sLength);
        System.arraycopy(bytes, sLength, key, 0, keyLength);
        BigInteger secret = ByteEncoding.fromByteArray(key);
        validatePrivateKey(secret);
        this.s = s;
    }

    /**
     * Construct private key from octets.
     * @param sikeParam SIKE parameters.
     * @param party Alice or Bob.
     * @param octets Octet value of the private key.
     */
    public SidhPrivateKey(SikeParam sikeParam, Party party, String octets) {
        this.sikeParam = sikeParam;
        this.party = party;
        int sLength = sikeParam.getMessageBytes();
        int keyLength = getKeyLength(party);
        if (octets == null || octets.length() != (sLength + keyLength) * 2) {
            throw new InvalidParameterException("Invalid private key");
        }
        byte[] bytes = octets.getBytes(StandardCharsets.UTF_8);
        byte[] s = new byte[sLength * 2];
        key = new byte[keyLength * 2];
        System.arraycopy(bytes, 0, s, 0, sLength * 2);
        System.arraycopy(bytes, sLength * 2, key, 0, keyLength * 2);
        BigInteger sVal = OctetEncoding.fromOctetString(new String(s));
        BigInteger secret = OctetEncoding.fromOctetString(new String(key));
        validatePrivateKey(secret);
        this.s = ByteEncoding.toByteArray(sVal, sLength);
    }

    /**
     * Construct private key from bytes with specified parameter s for SIKE decapsulation.
     * @param sikeParam SIKE parameters.
     * @param party Alice or Bob.
     * @param key Byte value of the private key.
     * @param s Parameter s for SIKE decapsulation.
     */
    public SidhPrivateKey(SikeParam sikeParam, Party party, BigInteger key, byte[] s) {
        this(sikeParam, party, key);
        this.s = s;
    }

    /**
     * Validate the BigInteger value representing the private key.
     * @param secret BigInteger value representing the private key.
     */
    private void validatePrivateKey(BigInteger secret) {
        if (secret.compareTo(BigInteger.ZERO) <= 0) {
            throw new InvalidParameterException("Invalid secret");
        }
        if (party == Party.ALICE) {
            if (secret.compareTo(sikeParam.getOrdA()) >= 0) {
                throw new InvalidParameterException("Invalid secret");
            }
        } else if (party == Party.BOB) {
            if (secret.compareTo(sikeParam.getOrdB()) >= 0) {
                throw new InvalidParameterException("Invalid secret");
            }
        } else {
            throw new InvalidParameterException("Invalid party");
        }
    }

    /**
     * Get the private key length.
     * @param party Alice or Bob.
     * @return Private key length.
     */
    private int getKeyLength(Party party) {
        if (party == Party.ALICE) {
            return (sikeParam.getMsbA() + 7) / 8;
        } else if (party == Party.BOB){
            return (sikeParam.getMsbB() - 1 + 7) / 8;
        } else {
            throw new InvalidParameterException("Invalid party");
        }
    }

    /**
     * Get the private key as byte array.
     * @return Private key as byte array.
     */
    public byte[] getKey() {
        return key;
    }

    /**
     * Get the private key as an F(p) element.
     * @return Private key as an F(p) element.
     */
    public FpElement getFpElement() {
        BigInteger secret = ByteEncoding.fromByteArray(key);
        return sikeParam.getFp2ElementFactory().generate(secret).getX0();
    }

    /**
     * Get the private key as a number.
     * @return Private key as a number.
     */
    public BigInteger getM() {
        return ByteEncoding.fromByteArray(key);
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
    @Override
    public byte[] getEncoded() {
        byte[] output = new byte[s.length + key.length];
        System.arraycopy(s, 0, output, 0, s.length);
        System.arraycopy(key, 0, output, s.length, key.length);
        return output;
    }

    /**
     * Convert private key into an octet string.
     * @return Octet string.
     */
    public String toOctetString() {
        String prefix = OctetEncoding.toOctetString(s, sikeParam.getMessageBytes());
        int length = getKeyLength(party);
        return prefix + OctetEncoding.toOctetString(key, length);
    }

    @Override
    public String toString() {
        return getM().toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SidhPrivateKey that = (SidhPrivateKey) o;
        System.out.println(sikeParam.equals(that.sikeParam));
        System.out.println(Arrays.equals(s, that.s));
        System.out.println(Arrays.equals(key, that.key));
        return sikeParam.equals(that.sikeParam)
                && Arrays.equals(s, that.s)
                && Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sikeParam, s, key);
    }
}
