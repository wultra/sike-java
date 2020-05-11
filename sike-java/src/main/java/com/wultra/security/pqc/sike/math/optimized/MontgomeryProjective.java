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
package com.wultra.security.pqc.sike.math.optimized;

import com.wultra.security.pqc.sike.math.Fp2Element;
import com.wultra.security.pqc.sike.math.api.Fp2Point;
import com.wultra.security.pqc.sike.math.api.Montgomery;
import com.wultra.security.pqc.sike.model.EvaluatedCurve;
import com.wultra.security.pqc.sike.model.MontgomeryCurve;
import com.wultra.security.pqc.sike.param.SikeParam;

import java.math.BigInteger;

/**
 * Optimized elliptic curve mathematics on Montgomery curves with projective coordinates.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class MontgomeryProjective implements Montgomery {

    // TODO - implement optimized algorithms

    @Override
    public Fp2Point doubleAndAdd(MontgomeryCurve curve, BigInteger m, Fp2Point p) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Point xDbl(MontgomeryCurve curve, Fp2Point p) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Point xTpl(MontgomeryCurve curve, Fp2Point p) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Point xDble(MontgomeryCurve curve, Fp2Point p, int e) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Point xTple(MontgomeryCurve curve, Fp2Point p, int e) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Point xAdd(MontgomeryCurve curve, Fp2Point p, Fp2Point q) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Point getXr(MontgomeryCurve curve, Fp2Point p, Fp2Point q) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Element jInv(MontgomeryCurve curve) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Element getA(SikeParam sikeParam, Fp2Element px, Fp2Element qx, Fp2Element rx) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public EvaluatedCurve getYpYqAB(SikeParam sikeParam, Fp2Element px, Fp2Element qx, Fp2Element rx) {
        throw new RuntimeException("Not implemented yet");
    }
}
