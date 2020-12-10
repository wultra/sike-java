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

import com.wultra.security.pqc.sike.math.optimized.fp.UnsignedLong;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test of unsigned 64-bit integer arithmetic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class UnsignedLongTest {

    @Test
    void testZeroAdd() {
        long x = 0L;
        long y = 0L;
        long carry = 0L;
        long[] result = UnsignedLong.add(x, y, carry);
        assertEquals(0L, result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testZeroOneAdd() {
        long x = 0L;
        long y = 1L;
        long carry = 0L;
        long[] result = UnsignedLong.add(x, y, carry);
        assertEquals(1L, result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testZeroOneAddAndCarry() {
        long x = 0L;
        long y = 1L;
        long carry = 1L;
        long[] result = UnsignedLong.add(x, y, carry);
        assertEquals(2L, result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testMaxValueAddZero() {
        long x = Long.parseUnsignedLong("18446744073709551615");
        long y = 0L;
        long carry = 0L;
        long[] result = UnsignedLong.add(x, y, carry);
        assertEquals(Long.parseUnsignedLong("18446744073709551615"), result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testMaxValueAddOne() {
        long x = Long.parseUnsignedLong("18446744073709551615");
        long y = 1L;
        long carry = 0L;
        long[] result = UnsignedLong.add(x, y, carry);
        assertEquals(0L, result[0]);
        assertEquals(1L, result[1]);
    }

    @Test
    void testMaxValueAddTwo() {
        long x = Long.parseUnsignedLong("18446744073709551615");
        long y = 2L;
        long carry = 0L;
        long[] result = UnsignedLong.add(x, y, carry);
        assertEquals(1L, result[0]);
        assertEquals(1L, result[1]);
    }

    @Test
    void testMaxValueAddZeroAndCarry() {
        long x = Long.parseUnsignedLong("18446744073709551615");
        long y = 0L;
        long carry = 1L;
        long[] result = UnsignedLong.add(x, y, carry);
        assertEquals(0L, result[0]);
        assertEquals(1L, result[1]);
    }

    @Test
    void testMaxValueAddOneAndCarry() {
        long x = Long.parseUnsignedLong("18446744073709551615");
        long y = 1L;
        long carry = 1L;
        long[] result = UnsignedLong.add(x, y, carry);
        assertEquals(1L, result[0]);
        assertEquals(1L, result[1]);
    }

    @Test
    void testMaxValueMinusOneAddZeroAndCarry() {
        long x = Long.parseUnsignedLong("18446744073709551614");
        long y = 0L;
        long carry = 1L;
        long[] result = UnsignedLong.add(x, y, carry);
        assertEquals(Long.parseUnsignedLong("18446744073709551615"), result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testZeroSub() {
        long x = 0L;
        long y = 0L;
        long borrow = 0L;
        long[] result = UnsignedLong.sub(x, y, borrow);
        assertEquals(0L, result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testOneZeroSub() {
        long x = 1L;
        long y = 0L;
        long borrow = 0L;
        long[] result = UnsignedLong.sub(x, y, borrow);
        assertEquals(1L, result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testOneZeroSubBorrow() {
        long x = 1L;
        long y = 0L;
        long borrow = 1L;
        long[] result = UnsignedLong.sub(x, y, borrow);
        assertEquals(0L, result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testZeroSubOne() {
        long x = 0L;
        long y = 1L;
        long borrow = 0L;
        long[] result = UnsignedLong.sub(x, y, borrow);
        assertEquals(Long.parseUnsignedLong("18446744073709551615"), result[0]);
        assertEquals(1L, result[1]);
    }

    @Test
    void testZeroSubZeroBorrow() {
        long x = 0L;
        long y = 0L;
        long borrow = 1L;
        long[] result = UnsignedLong.sub(x, y, borrow);
        assertEquals(Long.parseUnsignedLong("18446744073709551615"), result[0]);
        assertEquals(1L, result[1]);
    }

    @Test
    void testZeroSubOneBorrow() {
        long x = 0L;
        long y = 1L;
        long borrow = 1L;
        long[] result = UnsignedLong.sub(x, y, borrow);
        assertEquals(Long.parseUnsignedLong("18446744073709551614"), result[0]);
        assertEquals(1L, result[1]);
    }

    @Test
    void testMaxSubMax() {
        long x = Long.parseUnsignedLong("18446744073709551615");
        long y = Long.parseUnsignedLong("18446744073709551615");
        long borrow = 0L;
        long[] result = UnsignedLong.sub(x, y, borrow);
        assertEquals(0L, result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testMaxSubMaxMinusOneBorrow() {
        long x = Long.parseUnsignedLong("18446744073709551615");
        long y = Long.parseUnsignedLong("18446744073709551614");
        long borrow = 1L;
        long[] result = UnsignedLong.sub(x, y, borrow);
        assertEquals(0L, result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testMultiplyZeroByZero() {
        long x = 0L;
        long y = 0L;
        long[] result = UnsignedLong.mul(x, y);
        assertEquals(0L, result[0]);
        assertEquals(0L, result[1]);
    }

    @Test
    void testMultiplyOneByOne() {
        long x = 1L;
        long y = 1L;
        long[] result = UnsignedLong.mul(x, y);
        assertEquals(0L, result[0]);
        assertEquals(1L, result[1]);
    }

    @Test
    void testMultiplyBigValueByTwo() {
        long x = Long.parseUnsignedLong("9223372036854775807");
        long y = 2L;
        long[] result = UnsignedLong.mul(x, y);
        assertEquals(0L, result[0]);
        assertEquals(Long.parseUnsignedLong("18446744073709551614"), result[1]);
    }

    @Test
    void testMultiplyMaxByMax() {
        long x = Long.parseUnsignedLong("18446744073709551615");
        long y = Long.parseUnsignedLong("18446744073709551615");
        long[] result = UnsignedLong.mul(x, y);
        // ((2^64)-1)*((2^64)-1) / (2^64) = 18446744073709551614
        assertEquals(Long.parseUnsignedLong("18446744073709551614"), result[0]);
        // ((2^64)-1)*((2^64)-1) mod 2^64 = 1
        assertEquals(1L, result[1]);
    }

    @Test
    void testMultiplyHiLo1() {
        long x = Long.parseUnsignedLong("123456789123456789");
        long y = Long.parseUnsignedLong("987654321987654321");
        long[] result = UnsignedLong.mul(x, y);
        assertEquals(Long.parseUnsignedLong("6609981190679600"), result[0]);
        assertEquals(Long.parseUnsignedLong("14369616054794401669"), result[1]);
    }

    @Test
    void testMultiplyHiLo2() {
        long x = Long.parseUnsignedLong("11111111111");
        long y = Long.parseUnsignedLong("99999999999");
        long[] result = UnsignedLong.mul(x, y);
        assertEquals(Long.parseUnsignedLong("60"), result[0]);
        assertEquals(Long.parseUnsignedLong("4306466666315791929"), result[1]);
    }
    @Test
    void testMultiplyHiLo3() {
        long x = Long.parseUnsignedLong("555555555");
        long y = Long.parseUnsignedLong("555555555");
        long[] result = UnsignedLong.mul(x, y);
        assertEquals(0L, result[0]);
        assertEquals(Long.parseUnsignedLong("308641974691358025"), result[1]);
    }

}
