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

import com.wultra.security.pqc.sike.math.api.FpElement;
import com.wultra.security.pqc.sike.math.optimized.fp.FpElementOpti;
import com.wultra.security.pqc.sike.math.optimized.fp.FpMath;
import com.wultra.security.pqc.sike.model.ImplementationType;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.param.SikeParamP434;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test of field arithmetic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class FpMathTest {

    private final SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
    private final FpMath fpMath = new FpMath(sikeParam);

    @Test
    public void testZeroAddRdc() {
        FpElementOpti x = new FpElementOpti(sikeParam);
        FpElementOpti result = fpMath.fpAddRdc(x, x);
        assertEquals(x, result);
    }

    @Test
    public void testZeroAddOneRdc() {
        FpElementOpti x = new FpElementOpti(sikeParam);
        FpElementOpti y = new FpElementOpti(sikeParam);
        y.getValue()[y.size() - 1] = 1L;
        FpElementOpti result = fpMath.fpAddRdc(x, y);
        assertEquals(y, result);
    }

    @Test
    public void testAddPZeroRdc() {
        FpElementOpti x = sikeParam.getP();
        FpElementOpti y = new FpElementOpti(sikeParam);
        FpElementOpti result = fpMath.fpAddRdc(x, y);
        // The result is x, modulo is not applied
        assertEquals(x, result);
    }

    @Test
    public void testAddPx2ZeroRdc() {
        FpElementOpti x = sikeParam.getPx2();
        FpElementOpti y = new FpElementOpti(sikeParam);
        FpElementOpti result = fpMath.fpAddRdc(x, y);
        // The result is 0, modulo is applied
        assertEquals(y, result);
    }

    @Test
    public void testAddPx2OneRdc() {
        FpElementOpti x = sikeParam.getPx2();
        FpElementOpti y = new FpElementOpti(sikeParam);
        y.getValue()[y.size() - 1] = 1L;
        FpElementOpti result = fpMath.fpAddRdc(x, y);
        // The result is 1, modulo is applied
        assertEquals(y, result);
    }

    @Test
    public void testZeroSubRdc() {
        FpElementOpti x = new FpElementOpti(sikeParam);
        FpElementOpti result = fpMath.fpSubRdc(x, x);
        assertEquals(x, result);
    }

    @Test
    public void testZeroSubOneRdc() {
        FpElementOpti x = new FpElementOpti(sikeParam);
        FpElementOpti y = new FpElementOpti(sikeParam);
        y.getValue()[y.size() - 1] = 1L;
        FpElementOpti result = fpMath.fpSubRdc(x, y);
        FpElementOpti expected = sikeParam.getPx2();
        // Expected value is p*2 - 1
        expected.getValue()[expected.size() - 1] = expected.getValue()[expected.size() - 1] - 1L;
        assertEquals(expected, result);
    }

    @Test
    public void testZeroRdcP() {
        FpElementOpti x = new FpElementOpti(sikeParam);
        fpMath.fpRdcP(x);
        FpElementOpti expected = new FpElementOpti(sikeParam);
        assertEquals(expected, x);
    }

    @Test
    public void testPRdcP() {
        FpElementOpti x = sikeParam.getP();
        fpMath.fpRdcP(x);
        FpElementOpti expected = new FpElementOpti(sikeParam);
        assertEquals(expected, x);
    }

    @Test
    public void testFpSwapCondTrue() {
        FpElementOpti x = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("05ADF455C5C345BF", 16),
                Long.parseUnsignedLong("91935C5CC767AC2B", 16),
                Long.parseUnsignedLong("AFE4E879951F0257", 16),
                Long.parseUnsignedLong("70E792DC89FA27B1", 16),
                Long.parseUnsignedLong("F797F526BB48C8CD", 16),
                Long.parseUnsignedLong("2181DB6131AF621F", 16),
                Long.parseUnsignedLong("00000A1C08B1ECC4", 16)
        });
        FpElementOpti y = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("6E5497556EDD48A3", 16),
                Long.parseUnsignedLong("2A61B501546F1C05", 16),
                Long.parseUnsignedLong("EB919446D049887D", 16),
                Long.parseUnsignedLong("5864A4A69D450C4F", 16),
                Long.parseUnsignedLong("B883F276A6490D2B", 16),
                Long.parseUnsignedLong("22CC287022D5F5B9", 16),
                Long.parseUnsignedLong("0001BED4772E551F", 16)
        });
        FpElement xCopy = x.copy();
        FpElement yCopy = y.copy();
        fpMath.fpSwapCond(x, y, 1L);
        assertEquals(yCopy, x);
        assertEquals(xCopy, y);
    }

    @Test
    public void testFpSwapCondFalse() {
        FpElementOpti x = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("05ADF455C5C345BF", 16),
                Long.parseUnsignedLong("91935C5CC767AC2B", 16),
                Long.parseUnsignedLong("AFE4E879951F0257", 16),
                Long.parseUnsignedLong("70E792DC89FA27B1", 16),
                Long.parseUnsignedLong("F797F526BB48C8CD", 16),
                Long.parseUnsignedLong("2181DB6131AF621F", 16),
                Long.parseUnsignedLong("00000A1C08B1ECC4", 16)
        });
        FpElementOpti y = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("6E5497556EDD48A3", 16),
                Long.parseUnsignedLong("2A61B501546F1C05", 16),
                Long.parseUnsignedLong("EB919446D049887D", 16),
                Long.parseUnsignedLong("5864A4A69D450C4F", 16),
                Long.parseUnsignedLong("B883F276A6490D2B", 16),
                Long.parseUnsignedLong("22CC287022D5F5B9", 16),
                Long.parseUnsignedLong("0001BED4772E551F", 16)
        });
        FpElement xCopy = x.copy();
        FpElement yCopy = y.copy();
        fpMath.fpSwapCond(x, y, 0L);
        assertEquals(xCopy, x);
        assertEquals(yCopy, y);
    }

    @Test
    public void testFpMulZero() {
        FpElementOpti x = new FpElementOpti(sikeParam);
        FpElementOpti y = new FpElementOpti(sikeParam);
        FpElementOpti result = fpMath.fpMul(x, y);
        long[] value = new long[sikeParam.getFpWords() * 2];
        for (int i = 0; i < sikeParam.getFpWords() * 2; i++) {
            value[i] = 0L;
        }
        assertEquals(new FpElementOpti(sikeParam, value), result);
    }

    @Test
    public void testFpMulOne() {
        FpElementOpti x = new FpElementOpti(sikeParam);
        x.getValue()[x.size() - 1] = 1L;
        FpElementOpti y = new FpElementOpti(sikeParam);
        y.getValue()[y.size() - 1] = 1L;
        FpElementOpti result = fpMath.fpMul(x, y);
        long[] value = new long[sikeParam.getFpWords() * 2];
        for (int i = 0; i < sikeParam.getFpWords() * 2; i++) {
            value[i] = 0L;
        }
        FpElementOpti expected = new FpElementOpti(sikeParam, value);
        expected.getValue()[expected.size() - 2] = 1L;
        assertEquals(expected, result);
    }

    @Test
    public void testFpMulOneTwo() {
        FpElementOpti x = new FpElementOpti(sikeParam);
        x.getValue()[x.size() - 1] = 1L;
        FpElementOpti y = new FpElementOpti(sikeParam);
        y.getValue()[y.size() - 1] = 2L;
        FpElementOpti result = fpMath.fpMul(x, y);
        long[] value = new long[sikeParam.getFpWords() * 2];
        for (int i = 0; i < sikeParam.getFpWords() * 2; i++) {
            value[i] = 0L;
        }
        FpElementOpti expected = new FpElementOpti(sikeParam, value);
        expected.getValue()[expected.size() - 2] = 2L;
        assertEquals(expected, result);
    }

    @Test
    public void testFpMul() {
        FpElementOpti x = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("05ADF455C5C345BF", 16),
                Long.parseUnsignedLong("91935C5CC767AC2B", 16),
                Long.parseUnsignedLong("AFE4E879951F0257", 16),
                Long.parseUnsignedLong("70E792DC89FA27B1", 16),
                Long.parseUnsignedLong("F797F526BB48C8CD", 16),
                Long.parseUnsignedLong("2181DB6131AF621F", 16),
                Long.parseUnsignedLong("00000A1C08B1ECC4", 16)
        });
        FpElementOpti y = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("6E5497556EDD48A3", 16),
                Long.parseUnsignedLong("2A61B501546F1C05", 16),
                Long.parseUnsignedLong("EB919446D049887D", 16),
                Long.parseUnsignedLong("5864A4A69D450C4F", 16),
                Long.parseUnsignedLong("B883F276A6490D2B", 16),
                Long.parseUnsignedLong("22CC287022D5F5B9", 16),
                Long.parseUnsignedLong("0001BED4772E551F", 16)
        });
        FpElementOpti expected = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("202625321ED6209D", 16),
                Long.parseUnsignedLong("E5C308F0E445240D", 16),
                Long.parseUnsignedLong("AFEB6AE1CAB32EEE", 16),
                Long.parseUnsignedLong("639387B1A8C840D5", 16),
                Long.parseUnsignedLong("49688D3E3451B61C", 16),
                Long.parseUnsignedLong("ECFC874B5CA69C20", 16),
                Long.parseUnsignedLong("F5CF44DB153217C8", 16),
                Long.parseUnsignedLong("A63433819DD3DB5A", 16),
                Long.parseUnsignedLong("7C4C549B441B950B", 16),
                Long.parseUnsignedLong("C2B2CC10DE04DE6E", 16),
                Long.parseUnsignedLong("4B09D74EB1DD4601", 16),
                Long.parseUnsignedLong("F814733B29B69DB1", 16),
                Long.parseUnsignedLong("A46937B9CCE8C76", 16),
                Long.parseUnsignedLong("11A53B12", 16)
        });
        assertEquals(expected, fpMath.fpMul(x, y));
    }

    @Test
    public void testFpMontRed() {
        SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        FpElementOpti value = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("9946470042253566783"),
                Long.parseUnsignedLong("6968516007027963214"),
                Long.parseUnsignedLong("2128177586330530955"),
                Long.parseUnsignedLong("15927661658500696777"),
                Long.parseUnsignedLong("12316723092555895223"),
                Long.parseUnsignedLong("5614584294287028117"),
                Long.parseUnsignedLong("16261106872207110587"),
                Long.parseUnsignedLong("16055208308553732183"),
                Long.parseUnsignedLong("1346465154661575736"),
                Long.parseUnsignedLong("8406758572877889094"),
                Long.parseUnsignedLong("17270214720538722621"),
                Long.parseUnsignedLong("8880455854819143963"),
                Long.parseUnsignedLong("15171687671753763656"),
                Long.parseUnsignedLong("620243965526688")
        });
        FpElementOpti expected = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("15498328644779727983"),
                Long.parseUnsignedLong("5351278737051087079"),
                Long.parseUnsignedLong("8706761087432659938"),
                Long.parseUnsignedLong("5350588207879023383"),
                Long.parseUnsignedLong("18166660737044095734"),
                Long.parseUnsignedLong("1049466795586567251"),
                Long.parseUnsignedLong("1077930275256508")
        });
        FpMath fpMath = new FpMath(sikeParam);
        assertEquals(expected, fpMath.fpMontRdc(value));
    }

    @Test
    public void testFp2Sub() {
        SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        FpElementOpti x = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("9946470042253566784"),
                Long.parseUnsignedLong("6968516007027963214"),
                Long.parseUnsignedLong("2128177586330530955"),
                Long.parseUnsignedLong("16251097341384919753"),
                Long.parseUnsignedLong("12925631599570302063"),
                Long.parseUnsignedLong("8354813917732335336"),
                Long.parseUnsignedLong("499800934484970290"),
                Long.parseUnsignedLong("5414877442744294042"),
                Long.parseUnsignedLong("7629771832741187826"),
                Long.parseUnsignedLong("13470030206359139296"),
                Long.parseUnsignedLong("291637596215934808"),
                Long.parseUnsignedLong("7663770749615867752"),
                Long.parseUnsignedLong("3971009142509319027"),
                Long.parseUnsignedLong("6463362918")
        });
        FpElementOpti y = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("1"),
                Long.parseUnsignedLong("0"),
                Long.parseUnsignedLong("0"),
                Long.parseUnsignedLong("323435682884222976"),
                Long.parseUnsignedLong("608908507014406840"),
                Long.parseUnsignedLong("2740229623445307219"),
                Long.parseUnsignedLong("2685438135987411319"),
                Long.parseUnsignedLong("7806413207900113473"),
                Long.parseUnsignedLong("6283306678079612089"),
                Long.parseUnsignedLong("5063271633481250202"),
                Long.parseUnsignedLong("1306449107944652315"),
                Long.parseUnsignedLong("7702232678144296176"),
                Long.parseUnsignedLong("15099322769597229185"),
                Long.parseUnsignedLong("20855736329")
        });
        FpElementOpti expected = new FpElementOpti(sikeParam, new long[]{
                Long.parseUnsignedLong("9946470042253566783"),
                Long.parseUnsignedLong("6968516007027963214"),
                Long.parseUnsignedLong("2128177586330530955"),
                Long.parseUnsignedLong("15927661658500696777"),
                Long.parseUnsignedLong("12316723092555895223"),
                Long.parseUnsignedLong("5614584294287028117"),
                Long.parseUnsignedLong("16261106872207110587"),
                Long.parseUnsignedLong("16055208308553732183"),
                Long.parseUnsignedLong("1346465154661575736"),
                Long.parseUnsignedLong("8406758572877889094"),
                Long.parseUnsignedLong("17270214720538722621"),
                Long.parseUnsignedLong("8880455854819143963"),
                Long.parseUnsignedLong("15171687671753763656"),
                Long.parseUnsignedLong("620243965526688")
        });
        FpMath fpMath = new FpMath(sikeParam);
        assertEquals(expected, fpMath.fp2Sub(x, y));
    }

    // TODO - implement tests:
    // - fp2Add
    // - fpMulRdc

}
