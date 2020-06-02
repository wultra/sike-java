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
import com.wultra.security.pqc.sike.model.MontgomeryCurve;
import com.wultra.security.pqc.sike.model.optimized.MontgomeryConstants;
import com.wultra.security.pqc.sike.param.SikeParam;

import java.math.BigInteger;

/**
 * Optimized elliptic curve mathematics on Montgomery curves with projective coordinates.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class MontgomeryProjective implements Montgomery {

    @Override
    public Fp2Point xDbl(MontgomeryCurve curve, Fp2Point p) {
        // TODO - missing point at infinity check in specification, reported to SIKE team
        MontgomeryConstants constants = curve.getOptimizedConstants();
        Fp2Element a24plus = constants.getA24plus();
        Fp2Element c24 = constants.getC24();
        Fp2Element t0, t1, p2x, p2z;
        t0 = p.getX().subtract(p.getZ());
        t1 = p.getX().add(p.getZ());
        t0 = t0.square();
        t1 = t1.square();
        p2z = c24.multiply(t0);
        p2x = p2z.multiply(t1);
        t1 = t1.subtract(t0);
        t0 = a24plus.multiply(t1);
        p2z = p2z.add(t0);
        p2z = p2z.multiply(t1);
        return new Fp2PointProjective(p2x, p2z);
    }

    @Override
    public Fp2Point xTpl(MontgomeryCurve curve, Fp2Point p) {
        // TODO - missing point at infinity check in specification, reported to SIKE team
        MontgomeryConstants constants = curve.getOptimizedConstants();
        Fp2Element a24plus = constants.getA24plus();
        Fp2Element a24minus = constants.getA24minus();
        Fp2Element t0, t1, t2, t3, t4, t5, t6, p3x, p3z;
        t0 = p.getX().subtract(p.getZ());
        t2 = t0.square();
        t1 = p.getX().add(p.getZ());
        t3 = t1.square();
        t4 = t1.add(t0);
        t0 = t1.subtract(t0);
        t1 = t4.square();
        t1 = t1.subtract(t3);
        t1 = t1.subtract(t2);
        t5 = t3.multiply(a24plus);
        t3 = t5.multiply(t3);
        t6 = t2.multiply(a24minus);
        t2 = t2.multiply(t6);
        t3 = t2.subtract(t3);
        t2 = t5.subtract(t6);
        t1 = t2.multiply(t1);
        t2 = t3.add(t1);
        t2 = t2.square();
        p3x = t2.multiply(t4);
        t1 = t3.subtract(t1);
        t1 = t1.square();
        p3z = t1.multiply(t0);
        return new Fp2PointProjective(p3x, p3z);
    }

    @Override
    public Fp2Point xDble(MontgomeryCurve curve, Fp2Point p, int e) {
        Fp2Point pAp = p;
        for (int i = 0; i < e; i++) {
            pAp = xDbl(curve, pAp);
        }
        return pAp;
    }

    @Override
    public Fp2Point xTple(MontgomeryCurve curve, Fp2Point p, int e) {
        Fp2Point pAp = p;
        for (int i = 0; i < e; i++) {
            pAp = xTpl(curve, pAp);
        }
        return pAp;
    }

    @Override
    public Fp2Element jInv(MontgomeryCurve curve) {
        Fp2Element a = curve.getA();
        MontgomeryConstants constants = curve.getOptimizedConstants();
        Fp2Element c = constants.getC();
        Fp2Element t0, t1, j;
        j = a.square();
        t1 = c.square();
        t0 = t1.add(t1);
        t0 = j.subtract(t0);
        t0 = t0.subtract(t1);
        j = t0.subtract(t1);
        t1 = t1.square();
        j = j.multiply(t1);
        t0 = t0.add(t0);
        t0 = t0.add(t0);
        t1 = t0.square();
        t0 = t0.multiply(t1);
        t0 = t0.add(t0);
        t0 = t0.add(t0);
        j = j.inverse();
        j = t0.multiply(j);
        return j;
    }

    @Override
    public Fp2Element getA(SikeParam sikeParam, Fp2Element px, Fp2Element qx, Fp2Element rx) {
        Fp2Element t0, t1, ap;
        t1 = px.add(qx);
        t0 = px.multiply(qx);
        ap = rx.multiply(t1);
        ap = ap.add(t0);
        t0 = t0.multiply(rx);
        ap = ap.subtract(Fp2Element.one(sikeParam.getPrime()));
        t0 = t0.add(t0);
        t1 = t1.add(rx);
        t0 = t0.add(t0);
        ap = ap.square();
        t0 = t0.inverse();
        ap = ap.multiply(t0);
        ap = ap.subtract(t1);
        return ap;
    }

    /**
     * Combined coordinate doubling and differential addition.
     * @param p Point P.
     * @param q Point Q.
     * @param r Point P - Q.
     * @return Points P2 and P + Q.
     */
    private Fp2Point[] xDblAdd(Fp2Point p, Fp2Point q, Fp2Point r, Fp2Element a24plus) {
        Fp2Element t0, t1, t2, p2x, p2z, pqx, pqz;
        t0 = p.getX().add(p.getZ());
        t1 = p.getX().subtract(p.getZ());
        p2x = t0.square();
        t2 = q.getX().subtract(q.getZ());
        pqx = q.getX().add(q.getZ());
        t0 = t0.multiply(t2);
        p2z = t1.square();
        t1 = t1.multiply(pqx);
        t2 = p2x.subtract(p2z);
        p2x = p2x.multiply(p2z);
        pqx = a24plus.multiply(t2);
        pqz = t0.subtract(t1);
        p2z = pqx.add(p2z);
        pqx = t0.add(t1);
        p2z = p2z.multiply(t2);
        pqz = pqz.square();
        pqx = pqx.square();
        pqz = r.getX().multiply(pqz);
        pqx = r.getZ().multiply(pqx);
        Fp2PointProjective p2 = new Fp2PointProjective(p2x, p2z);
        Fp2PointProjective pq = new Fp2PointProjective(pqx, pqz);
        return new Fp2PointProjective[]{p2, pq};
    }

    /**
     * Three point Montgomery ladder.
     * @param curve Current curve.
     * @param m Scalar value.
     * @param px The x coordinate of point P.
     * @param qx The x coordinate of point Q.
     * @param rx The x coordinate of point P - Q.
     * @param msb Most significant bit.
     * @return Calculated new point.
     */
    public Fp2Point ladder3Pt(MontgomeryCurve curve, BigInteger m, Fp2Element px, Fp2Element qx, Fp2Element rx, int msb) {
        BigInteger prime = curve.getSikeParam().getPrime();
        Fp2Element a = curve.getA();
        Fp2Point p0, p1, p2;
        Fp2Element a24plus;
        p0 = new Fp2PointProjective(qx, Fp2Element.one(prime));
        p1 = new Fp2PointProjective(px, Fp2Element.one(prime));
        p2 = new Fp2PointProjective(rx, Fp2Element.one(prime));
        a24plus = a.add(Fp2Element.generate(prime, 2));
        a24plus = a24plus.multiply(Fp2Element.generate(prime, 4).inverse());
        for (int i = 0; i < msb; i++) {
            if (m.testBit(i)) {
                Fp2Point[] points = xDblAdd(p0, p1, p2, a24plus);
                p0 = points[0];
                p1 = points[1];
            } else {
                Fp2Point[] points = xDblAdd(p0, p2, p1, a24plus);
                p0 = points[0];
                p2 = points[1];
            }
        }
        return p1;
    }

}
