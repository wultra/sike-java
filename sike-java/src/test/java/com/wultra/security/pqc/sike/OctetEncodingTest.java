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
package com.wultra.security.pqc.sike;

import com.wultra.security.pqc.sike.math.optimized.fp.FpElementOpti;
import com.wultra.security.pqc.sike.model.ImplementationType;
import com.wultra.security.pqc.sike.param.*;
import com.wultra.security.pqc.sike.util.OctetEncoding;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test of octet encoding.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class OctetEncodingTest {

    @Test
    void testConversionToString() {
        assertEquals("000000", OctetEncoding.toOctetString(BigInteger.ZERO, 3));
        assertEquals("010000000000", OctetEncoding.toOctetString(BigInteger.ONE, 6));
        assertEquals("02010000000000000000", OctetEncoding.toOctetString(new BigInteger("258"), 10));
        assertEquals("F5D2847EB0AD708A836E3A42DCF8A06DD6A442E58584EEFCFB93E3643370A9D2B2D7A1FBD32FCA430B640DF746789886F55B0F9123AB00", OctetEncoding.toOctetString(new BigInteger("7414245793236218931759067416133656081091359987964242955586558871517284227355106165661062279519102988920114614398938767562664891125"), 55));
        assertEquals("CF6121E44395DFAE78152A1162C49E3196B6065E8781FA4FC53F971E1766818E81388CB3BE212446A06AFBCEC958BE4E6539A590619100", OctetEncoding.toOctetString(new BigInteger("6298340736269152096363706376601736707467340295126624700837062780723222842097560939735075361277996916624015901459649381975340442063"), 55));
    }

    @Test
    void testConversionFromString() {
        assertEquals(BigInteger.ZERO, OctetEncoding.fromOctetString("000000"));
        assertEquals(BigInteger.ONE, OctetEncoding.fromOctetString("010000000000"));
        assertEquals(new BigInteger("258"), OctetEncoding.fromOctetString("02010000000000000000"));
        assertEquals(new BigInteger("7414245793236218931759067416133656081091359987964242955586558871517284227355106165661062279519102988920114614398938767562664891125"), OctetEncoding.fromOctetString("F5D2847EB0AD708A836E3A42DCF8A06DD6A442E58584EEFCFB93E3643370A9D2B2D7A1FBD32FCA430B640DF746789886F55B0F9123AB00"));
        assertEquals(new BigInteger("6298340736269152096363706376601736707467340295126624700837062780723222842097560939735075361277996916624015901459649381975340442063"), OctetEncoding.fromOctetString("CF6121E44395DFAE78152A1162C49E3196B6065E8781FA4FC53F971E1766818E81388CB3BE212446A06AFBCEC958BE4E6539A590619100"));
    }

    @Test
    void testConversions() {
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < 100; i++) {
            BigInteger r = new BigInteger(i, secureRandom);
            int mlen = i / 8 + 1;
            assertEquals(r, OctetEncoding.fromOctetString(OctetEncoding.toOctetString(r, mlen)));
        }
    }

    @Test
    void testConversionToMontgomeryP434One() {
        SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        FpElementOpti one = new FpElementOpti(sikeParam, new BigInteger("1"));
        assertArrayEquals(new long[]{
                Long.parseUnsignedLong("000000000000742C", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("B90FF404FC000000", 16),
                Long.parseUnsignedLong("D801A4FB559FACD4", 16),
                Long.parseUnsignedLong("E93254545F77410C", 16),
                Long.parseUnsignedLong("0000ECEEA7BD2EDA", 16)
        }, one.getValue());
        String octetString = one.toOctetString();
        assertEquals("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(new BigInteger("1"), OctetEncoding.fromOctetString(octetString));
    }

    @Test
    void testConversionFromMontgomeryP434() {
        SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        FpElementOpti six = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("000000000002B90A", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("5ADCCB2822000000", 16),
                Long.parseUnsignedLong("187D24F39F0CAFB4", 16),
                Long.parseUnsignedLong("9D353A4D394145A0", 16),
                Long.parseUnsignedLong("00012559A0403298", 16)
        });
        String octetString = six.toOctetString();
        assertEquals("06000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(new BigInteger("6"), OctetEncoding.fromOctetString(octetString));
    }

    @Test
    void testConversionToMontgomeryP434Six() {
        SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        FpElementOpti six = new FpElementOpti(sikeParam, new BigInteger("6"));
        assertArrayEquals(new long[]{
                Long.parseUnsignedLong("000000000002B90A", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("5ADCCB2822000000", 16),
                Long.parseUnsignedLong("187D24F39F0CAFB4", 16),
                Long.parseUnsignedLong("9D353A4D394145A0", 16),
                Long.parseUnsignedLong("00012559A0403298", 16)
        }, six.getValue());
        String octetString = six.toOctetString();
        assertEquals("06000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(new BigInteger("6"), OctetEncoding.fromOctetString(octetString));
    }

    @Test
    void testConversionFromMontgomeryP503() {
        SikeParam sikeParam = new SikeParamP503(ImplementationType.OPTIMIZED);
        FpElementOpti six = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("00000000000017D8", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("E000000000000000", 16),
                Long.parseUnsignedLong("30B1E6E3A51520FA", 16),
                Long.parseUnsignedLong("B13BC3BF6FFB3992", 16),
                Long.parseUnsignedLong("8045412EEB3E3DED", 16),
                Long.parseUnsignedLong("0069182E2159DBB8", 16)
        });
        String octetString = six.toOctetString();
        assertEquals("060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(new BigInteger("6"), OctetEncoding.fromOctetString(octetString));
    }

    @Test
    void testConversionFromMontgomeryP610() {
        SikeParam sikeParam = new SikeParamP610(ImplementationType.OPTIMIZED);
        FpElementOpti one = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("00000000670CC8E6", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("9A34000000000000", 16),
                Long.parseUnsignedLong("4D99C2BD28717A3F", 16),
                Long.parseUnsignedLong("0A4A1839A323D41C", 16),
                Long.parseUnsignedLong("D2B62215D06AD1E2", 16),
                Long.parseUnsignedLong("1369026E862CAF3D", 16),
                Long.parseUnsignedLong("000000010894E964", 16)
        });
        String octetString = one.toOctetString();
        assertEquals("0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(BigInteger.ONE, OctetEncoding.fromOctetString(octetString));
    }

    @Test
    void testConversionFromMontgomeryP751() {
        SikeParam sikeParam = new SikeParamP751(ImplementationType.OPTIMIZED);
        FpElementOpti one = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("00000000000249AD", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("0000000000000000", 16),
                Long.parseUnsignedLong("8310000000000000", 16),
                Long.parseUnsignedLong("5527B1E4375C6C66", 16),
                Long.parseUnsignedLong("697797BF3F4F24D0", 16),
                Long.parseUnsignedLong("C89DB7B2AC5C4E2E", 16),
                Long.parseUnsignedLong("4CA4B439D2076956", 16),
                Long.parseUnsignedLong("10F7926C7512C7E9", 16),
                Long.parseUnsignedLong("00002D5B24BCE5E2", 16)
        });
        String octetString = one.toOctetString();
        assertEquals("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(new BigInteger("1"), OctetEncoding.fromOctetString(octetString));
    }

    // TODO - more conversion tests

}
