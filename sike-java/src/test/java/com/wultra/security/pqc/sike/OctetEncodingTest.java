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
                0x000000000000742CL,
                0x0000000000000000L,
                0x0000000000000000L,
                0xB90FF404FC000000L,
                0xD801A4FB559FACD4L,
                0xE93254545F77410CL,
                0x0000ECEEA7BD2EDAL
        }, one.getValue());
        String octetString = one.toOctetString();
        assertEquals("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(new BigInteger("1"), OctetEncoding.fromOctetString(octetString));
    }

    @Test
    void testConversionFromMontgomeryP434() {
        SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        FpElementOpti six = new FpElementOpti(sikeParam, new long[]{
                0x000000000002B90AL,
                0x0000000000000000L,
                0x0000000000000000L,
                0x5ADCCB2822000000L,
                0x187D24F39F0CAFB4L,
                0x9D353A4D394145A0L,
                0x00012559A0403298L
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
                0x000000000002B90AL,
                0x0000000000000000L,
                0x0000000000000000L,
                0x5ADCCB2822000000L,
                0x187D24F39F0CAFB4L,
                0x9D353A4D394145A0L,
                0x00012559A0403298L
        }, six.getValue());
        String octetString = six.toOctetString();
        assertEquals("06000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(new BigInteger("6"), OctetEncoding.fromOctetString(octetString));
    }

    @Test
    void testConversionFromMontgomeryP503() {
        SikeParam sikeParam = new SikeParamP503(ImplementationType.OPTIMIZED);
        FpElementOpti six = new FpElementOpti(sikeParam, new long[]{
                0x00000000000017D8L,
                0x0000000000000000L,
                0x0000000000000000L,
                0xE000000000000000L,
                0x30B1E6E3A51520FAL,
                0xB13BC3BF6FFB3992L,
                0x8045412EEB3E3DEDL,
                0x0069182E2159DBB8L
        });
        String octetString = six.toOctetString();
        assertEquals("060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(new BigInteger("6"), OctetEncoding.fromOctetString(octetString));
    }

    @Test
    void testConversionFromMontgomeryP610() {
        SikeParam sikeParam = new SikeParamP610(ImplementationType.OPTIMIZED);
        FpElementOpti one = new FpElementOpti(sikeParam, new long[]{
                0x00000000670CC8E6L,
                0x0000000000000000L,
                0x0000000000000000L,
                0x0000000000000000L,
                0x9A34000000000000L,
                0x4D99C2BD28717A3FL,
                0x0A4A1839A323D41CL,
                0xD2B62215D06AD1E2L,
                0x1369026E862CAF3DL,
                0x000000010894E964L
        });
        String octetString = one.toOctetString();
        assertEquals("0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(BigInteger.ONE, OctetEncoding.fromOctetString(octetString));
    }

    @Test
    void testConversionFromMontgomeryP751() {
        SikeParam sikeParam = new SikeParamP751(ImplementationType.OPTIMIZED);
        FpElementOpti one = new FpElementOpti(sikeParam, new long[]{
                0x00000000000249ADL,
                0x0000000000000000L,
                0x0000000000000000L,
                0x0000000000000000L,
                0x0000000000000000L,
                0x8310000000000000L,
                0x5527B1E4375C6C66L,
                0x697797BF3F4F24D0L,
                0xC89DB7B2AC5C4E2EL,
                0x4CA4B439D2076956L,
                0x10F7926C7512C7E9L,
                0x00002D5B24BCE5E2L
        });
        String octetString = one.toOctetString();
        assertEquals("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", octetString);
        assertEquals(new BigInteger("1"), OctetEncoding.fromOctetString(octetString));
    }

    // TODO - more conversion tests

}
