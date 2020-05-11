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
package com.wultra.security.pqc.sike.math.api;

import com.wultra.security.pqc.sike.math.Fp2Element;
import com.wultra.security.pqc.sike.model.EvaluatedCurve;
import com.wultra.security.pqc.sike.model.MontgomeryCurve;
import com.wultra.security.pqc.sike.param.SikeParam;

import java.math.BigInteger;

/**
 * Elliptic curve mathematics on Montgomery curves.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface Montgomery {

    /**
     * Double-and-add scalar multiplication.
     * @param curve Current curve.
     * @param m Scalar value.
     * @param p Point on the curve.
     * @return Calculated new point.
     */
    Fp2Point doubleAndAdd(MontgomeryCurve curve, BigInteger m, Fp2Point p);

    /**
     * Double a point.
     * @param curve Current curve.
     * @param p Point on the curve.
     * @return Calculated new point.
     */
    Fp2Point xDbl(MontgomeryCurve curve, Fp2Point p);

    /**
     * Triple a point.
     * @param curve Current curve.
     * @param p Point on the curve.
     * @return Calculated new point.
     */
    Fp2Point xTpl(MontgomeryCurve curve, Fp2Point p);

    /**
     * Repeated doubling of a point.
     * @param curve Current curve.
     * @param p Point on the curve.
     * @param e Number of iterations.
     * @return Calculated new point.
     */
    Fp2Point xDble(MontgomeryCurve curve, Fp2Point p, int e);

    /**
     * Repeated trippling of a point.
     * @param curve Current curve.
     * @param p Point on the curve.
     * @param e Number of iterations.
     * @return Calculated new point.
     */
    Fp2Point xTple(MontgomeryCurve curve, Fp2Point p, int e);

    /**
     * Adding of two points.
     * @param curve Current curve.
     * @param p First point on the curve.
     * @param q Second point on the curve.
     * @return Calculated new point.
     */
    Fp2Point xAdd(MontgomeryCurve curve, Fp2Point p, Fp2Point q);

    /**
     * Recover the point R = P - Q.
     * @param curve Current curve.
     * @param p Point P.
     * @param q Point Q.
     * @return Calculated point R.
     */
    Fp2Point getXr(MontgomeryCurve curve, Fp2Point p, Fp2Point q);

    /**
     * Calculate a j-invariant of a curve.
     * @param curve Current curve.
     * @return Calculated j-invariant.
     */
    Fp2Element jInv(MontgomeryCurve curve);

    /**
     * Recover the Montgomery curve coefficient a.
     * @param sikeParam SIKE parameters.
     * @param px The x coordinate of point P.
     * @param qx The x coordinate of point Q.
     * @param rx The x coordinate of point R.
     * @return Recovered coefficient a.
     */
    Fp2Element getA(SikeParam sikeParam, Fp2Element px, Fp2Element qx, Fp2Element rx);

    /**
     * Recover the curve and points P and Q.
     * @param sikeParam SIKE parameters.
     * @param px The x coordinate of point P.
     * @param qx The x coordinate of point Q.
     * @param rx The x coordinate of point R.
     * @return A recovered curve and points P and Q.
     */
    EvaluatedCurve getYpYqAB(SikeParam sikeParam, Fp2Element px, Fp2Element qx, Fp2Element rx);

}
