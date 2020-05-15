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

import com.wultra.security.pqc.sike.util.OctetEncoding;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test of octet encoding.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class OctetEncodingTest {

    @Test
    public void testConversionToString() {
        assertEquals("000000", OctetEncoding.toOctetString(BigInteger.ZERO, 3));
        assertEquals("010000000000", OctetEncoding.toOctetString(BigInteger.ONE, 6));
        assertEquals("02010000000000000000", OctetEncoding.toOctetString(new BigInteger("258"), 10));
        assertEquals("F5D2847EB0AD708A836E3A42DCF8A06DD6A442E58584EEFCFB93E3643370A9D2B2D7A1FBD32FCA430B640DF746789886F55B0F9123AB00", OctetEncoding.toOctetString(new BigInteger("7414245793236218931759067416133656081091359987964242955586558871517284227355106165661062279519102988920114614398938767562664891125"), 55));
        assertEquals("CF6121E44395DFAE78152A1162C49E3196B6065E8781FA4FC53F971E1766818E81388CB3BE212446A06AFBCEC958BE4E6539A590619100", OctetEncoding.toOctetString(new BigInteger("6298340736269152096363706376601736707467340295126624700837062780723222842097560939735075361277996916624015901459649381975340442063"), 55));
    }

    @Test
    public void testConversionFromString() {
        assertEquals(BigInteger.ZERO, OctetEncoding.fromOctetString("000000"));
        assertEquals(BigInteger.ONE, OctetEncoding.fromOctetString("010000000000"));
        assertEquals(new BigInteger("258"), OctetEncoding.fromOctetString("02010000000000000000"));
        assertEquals(new BigInteger("7414245793236218931759067416133656081091359987964242955586558871517284227355106165661062279519102988920114614398938767562664891125"), OctetEncoding.fromOctetString("F5D2847EB0AD708A836E3A42DCF8A06DD6A442E58584EEFCFB93E3643370A9D2B2D7A1FBD32FCA430B640DF746789886F55B0F9123AB00"));
        assertEquals(new BigInteger("6298340736269152096363706376601736707467340295126624700837062780723222842097560939735075361277996916624015901459649381975340442063"), OctetEncoding.fromOctetString("CF6121E44395DFAE78152A1162C49E3196B6065E8781FA4FC53F971E1766818E81388CB3BE212446A06AFBCEC958BE4E6539A590619100"));
    }

    @Test
    public void testConversions() {
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < 100; i++) {
            BigInteger r = new BigInteger(i, secureRandom);
            int mlen = i / 8 + 1;
            assertEquals(r, OctetEncoding.fromOctetString(OctetEncoding.toOctetString(r, mlen)));
        }
    }
}
