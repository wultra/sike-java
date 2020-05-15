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
package com.wultra.security.pqc.sike.kat.model;

import java.util.Objects;

/**
 * Class representing a KAT response record.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class KatRspRecord {

    private int count;
    private String seed;
    private String pk;
    private String sk;
    private String ct;
    private String ss;

    /**
     * Default constructor.
     */
    public KatRspRecord() {
    }

    /**
     * Constructor with all details.
     * @param count Counter.
     * @param seed Seed.
     * @param pk Public key.
     * @param sk Private key.
     * @param ct Encrypted message.
     * @param ss Shared secret.
     */
    public KatRspRecord(int count, String seed, String pk, String sk, String ct, String ss) {
        this.count = count;
        this.seed = seed;
        this.pk = pk;
        this.sk = sk;
        this.ct = ct;
        this.ss = ss;
    }

    /**
     * Get the counter.
     * @return Counter.
     */
    public int getCount() {
        return count;
    }

    /**
     * Set the counter.
     * @param count Counter.
     */
    public void setCount(int count) {
        this.count = count;
    }

    /**
     * Get the seed.
     * @return Seed.
     */
    public String getSeed() {
        return seed;
    }

    /**
     * Set the seed.
     * @param seed Seed.
     */
    public void setSeed(String seed) {
        this.seed = seed;
    }

    /**
     * Get the public key.
     * @return Public key.
     */
    public String getPk() {
        return pk;
    }

    /**
     * Set the public key.
     * @param pk Public key.
     */
    public void setPk(String pk) {
        this.pk = pk;
    }

    /**
     * Get the private key.
     * @return Private key.
     */
    public String getSk() {
        return sk;
    }

    /**
     * Set the private key.
     * @param sk Private key.
     */
    public void setSk(String sk) {
        this.sk = sk;
    }

    /**
     * Get the encrypted message.
     * @return Encrypted message.
     */
    public String getCt() {
        return ct;
    }

    /**
     * Set the encrypted message.
     * @param ct Encrypted message.
     */
    public void setCt(String ct) {
        this.ct = ct;
    }

    /**
     * Get the shared secret.
     * @return Shared secret.
     */
    public String getSs() {
        return ss;
    }

    /**
     * Set the shared secret.
     * @param ss Shared secret.
     */
    public void setSs(String ss) {
        this.ss = ss;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KatRspRecord katRecord = (KatRspRecord) o;
        return seed.equals(katRecord.seed) &&
                pk.equals(katRecord.pk) &&
                ct.equals(katRecord.ct) &&
                ss.equals(katRecord.ss);
    }

    @Override
    public int hashCode() {
        return Objects.hash(seed, pk, ct, ss);
    }
}
