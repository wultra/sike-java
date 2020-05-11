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
import com.wultra.security.pqc.sike.math.FpElement;
import com.wultra.security.pqc.sike.math.api.Isogeny;
import com.wultra.security.pqc.sike.model.EvaluatedCurve;
import com.wultra.security.pqc.sike.model.MontgomeryCurve;
import com.wultra.security.pqc.sike.param.SikeParam;

import java.math.BigInteger;

/**
 * Optimized elliptic curve isogeny operations on Montgomery curves with projective coordinates.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class IsogenyProjective implements Isogeny {

    // TODO - implement optimized algorithms

    @Override
    public MontgomeryCurve curve2Iso(MontgomeryCurve curve, Fp2Point p2) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public MontgomeryCurve curve3Iso(MontgomeryCurve curve, Fp2Point p3) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public MontgomeryCurve curve4Iso(MontgomeryCurve curve, Fp2Point p4) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Point eval2Iso(Fp2Point q, Fp2Point p2) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Point eval3Iso(BigInteger prime, Fp2Point q, Fp2Point p3) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Point eval4Iso(BigInteger prime, Fp2Point q, Fp2Point p4) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public EvaluatedCurve iso2e(MontgomeryCurve curve, Fp2Point s) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public EvaluatedCurve iso2e(MontgomeryCurve curve, Fp2Point s, Fp2Point p, Fp2Point q) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public EvaluatedCurve iso3e(MontgomeryCurve curve, Fp2Point s) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public EvaluatedCurve iso3e(MontgomeryCurve curve, Fp2Point s, Fp2Point p, Fp2Point q) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Element isoEx2(SikeParam sikeParam, FpElement sk2, Fp2Element p2, Fp2Element q2, Fp2Element r2) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public Fp2Element isoEx3(SikeParam sikeParam, FpElement sk3, Fp2Element p3, Fp2Element q3, Fp2Element r3) {
        throw new RuntimeException("Not implemented yet");
    }
}
