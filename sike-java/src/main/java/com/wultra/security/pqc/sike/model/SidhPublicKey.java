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

import com.wultra.security.pqc.sike.math.Fp2Element;
import com.wultra.security.pqc.sike.param.SikeParam;

import java.security.PublicKey;
import java.util.Objects;

/**
 * SIDH or SIKE public key.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SidhPublicKey implements PublicKey {

    private final SikeParam sikeParam;

    private final Fp2Element px;
    private final Fp2Element qx;
    private final Fp2Element rx;

    /**
     * Public key constructor.
     * @param sikeParam SIKE parameters.
     * @param px The x coordinate of public point P.
     * @param qx The x coordinate of public point Q.
     * @param rx The x coordinate of public point R.
     */
    public SidhPublicKey(SikeParam sikeParam, Fp2Element px, Fp2Element qx, Fp2Element rx) {
        this.sikeParam = sikeParam;
        this.px = px;
        this.qx = qx;
        this.rx = rx;
    }

    // TODO add constructor with official octet format from SIKE specification

    /**
     * Get the x coordinate of public point P.
     * @return The x coordinate of public point P.
     */
    public Fp2Element getPx() {
        return px;
    }

    /**
     * The x coordinate of public point Q.
     * @return The x coordinate of public point Q.
     */
    public Fp2Element getQx() {
        return qx;
    }

    /**
     * The x coordinate of public point R.
     * @return The x coordinate of public point R.
     */
    public Fp2Element getRx() {
        return rx;
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
     * Get the public key encoded as bytes.
     * @return Public key encoded as bytes.
     */
    public byte[] getEncoded() {
        int primeSize = sikeParam.getPrime().bitLength() / 8 + 1;
        byte[] encoded = new byte[primeSize * 6];
        byte[] pxEncoded = px.getEncoded();
        byte[] qxEncoded = qx.getEncoded();
        byte[] rxEncoded = rx.getEncoded();
        System.arraycopy(pxEncoded, 0, encoded, 0, primeSize * 2);
        System.arraycopy(qxEncoded, 0, encoded, primeSize * 2, primeSize * 2);
        System.arraycopy(rxEncoded, 0, encoded, primeSize * 4, primeSize * 2);
        return encoded;
    }

    // TODO encode public key using official octet format from SIKE specification

    @Override
    public String toString() {
        return "(" + px.toString() + ", " + qx.toString() + ", " + rx.toString() + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SidhPublicKey publicKey = (SidhPublicKey) o;
        return px.equals(publicKey.px) &&
                qx.equals(publicKey.qx) &&
                rx.equals(publicKey.rx);
    }

    @Override
    public int hashCode() {
        return Objects.hash(px, qx, rx);
    }
}
