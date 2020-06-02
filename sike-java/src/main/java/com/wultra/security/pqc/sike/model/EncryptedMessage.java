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

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * SIKE encrypted message.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EncryptedMessage {

    private final PublicKey c0;
    private final byte[] c1;

    /**
     * SIKE encrypted message constructor.
     * @param c0 Alice's public key.
     * @param c1 Encrypted data.
     */
    public EncryptedMessage(PublicKey c0, byte[] c1) {
        this.c0 = c0;
        this.c1 = c1;
    }

    /**
     * Get Alice's public key.
     * @return Public key.
     */
    public PublicKey getC0() {
        return c0;
    }

    /**
     * Get encrypted data.
     * @return Encrypted data.
     */
    public byte[] getC1() {
        return c1;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedMessage that = (EncryptedMessage) o;
        return c0.equals(that.c0) &&
                Arrays.equals(c1, that.c1);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(c0);
        result = 31 * result + Arrays.hashCode(c1);
        return result;
    }
}
