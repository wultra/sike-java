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
package com.wultra.security.pqc.sike.util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * A simple SP800-90A based CTR DRBG SecureRandom with fixed parameters and without DF.
 *
 * This random generator is not secure and is only used for deterministic generation of cryptographic material
 * used for KAT tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class CrtDrbgRandom extends SecureRandom {

    private static final int KEY_SIZE = 32;
    private static final int VALUE_SIZE = 16;
    private static final int SEED_SIZE = KEY_SIZE + VALUE_SIZE;

    private final Cipher cipher;
    private byte[] key;
    private byte[] value;

    /**
     * CTR DRBG SecureRandom constructor.
     * @param seed Seed for deterministic random generation.
     * @throws GeneralSecurityException Throw in case encryption fails.
     */
    public CrtDrbgRandom(byte[] seed) throws GeneralSecurityException {
        cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        ctrDrbgInstantiateAlgorithm(seed);
    }

    /**
     * Generate random bytes.
     * @param bytes Byte array to fill with random bytes.
     */
    public void nextBytes(byte[] bytes) {
        synchronized (this) {
            try {
                generate(bytes);
            } catch (GeneralSecurityException e) {
                // Ignored, AES algorithm is available in case this class was successfully constructed
            }
        }
    }

    /**
     * Instantiate CTR DRBG algorithm without derivation function.
     * @param seed Seed for deterministic random generation.
     * @throws GeneralSecurityException Throw in case encryption fails.
     */
    private void ctrDrbgInstantiateAlgorithm(byte[] seed) throws GeneralSecurityException {
        key = new byte[KEY_SIZE];
        value = new byte[VALUE_SIZE];
        ctrDrbgUpdate(seed);
    }

    /**
     * Generate random bytes.
     * @param output Output byte array.
     * @throws GeneralSecurityException Throw in case encryption fails.
     */
    private void generate(byte[] output) throws GeneralSecurityException {
        byte[] val = new byte[VALUE_SIZE];
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

        for (int i = 0; i <= output.length / val.length; i++) {
            int bytesToCopy = Math.min((output.length - i * VALUE_SIZE), VALUE_SIZE);

            if (bytesToCopy != 0) {
                addOne(value);
                cipher.doFinal(value, 0, value.length, val);
                System.arraycopy(val, 0, output, i * val.length, bytesToCopy);
            }
        }

        ctrDrbgUpdate(null);

    }

    /**
     * Update CTR DRBG state.
     * @param data Input data.
     * @throws GeneralSecurityException Thrown in case encryption fails.
     */
    private void ctrDrbgUpdate(byte[] data) throws GeneralSecurityException {
        byte[] temp = new byte[SEED_SIZE];
        byte[] outputBlock = new byte[cipher.getBlockSize()];
        int i = 0;
        int outLen = cipher.getBlockSize();

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

        while (i * outLen < SEED_SIZE) {
            addOne(value);
            cipher.doFinal(value, 0, 16, outputBlock);
            int bytesToCopy = Math.min((temp.length - i * outLen), outLen);
            System.arraycopy(outputBlock, 0, temp, i * outLen, bytesToCopy);
            i++;
        }

        if (data != null) {
            temp = xor(data, temp);
        }

        System.arraycopy(temp, 0, key, 0, KEY_SIZE);
        System.arraycopy(temp, KEY_SIZE, value, 0, VALUE_SIZE);
    }

    /**
     * Add number one to a byte array.
     * @param bytes Byte array to update.
     */
    private void addOne(byte[] bytes) {
        int carry = 1;
        for (int i = 1; i <= bytes.length; i++) {
            int res = (bytes[bytes.length - i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            bytes[bytes.length - i] = (byte) res;
        }
    }

    /**
     * XOR two byte arrays.
     * @param a First byte array.
     * @param b Second byte array.
     * @return Byte array with result.
     */
    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[SEED_SIZE];
        for (int i = 0; i < SEED_SIZE; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

}
