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

import com.wultra.security.pqc.sike.math.api.Fp2Element;
import com.wultra.security.pqc.sike.math.api.FpElement;
import com.wultra.security.pqc.sike.math.optimized.fp.Fp2ElementOpti;
import com.wultra.security.pqc.sike.math.optimized.fp.FpElementOpti;
import com.wultra.security.pqc.sike.model.ImplementationType;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.param.SikeParamP434;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test of Fp2Element mathematics.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class Fp2MathTest {

    private final SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);

    @Test
    void testAddZero() {
        FpElement x = new FpElementOpti(sikeParam);
        Fp2Element x2 = new Fp2ElementOpti(sikeParam, x, x);
        Fp2Element result = x2.add(x2);
        assertEquals(x2, result);
    }

    @Test
    void testAddOneAndOne() {
        FpElementOpti x = new FpElementOpti(sikeParam);
        x.getValue()[x.size() - 1] = 1L;
        Fp2Element x2 = new Fp2ElementOpti(sikeParam, x, x);
        Fp2Element result = x2.add(x2);
        FpElementOpti expected = new FpElementOpti(sikeParam);
        expected.getValue()[expected.size() - 1] = 2L;
        Fp2Element expected2 = new Fp2ElementOpti(sikeParam, expected, expected);
        assertEquals(expected2, result);
    }

    @Test
    void testSubZero() {
        FpElement x = new FpElementOpti(sikeParam);
        Fp2Element x2 = new Fp2ElementOpti(sikeParam, x, x);
        Fp2Element result = x2.subtract(x2);
        assertEquals(x2, result);
    }

    // TODO more Fp2Element math tests
}
