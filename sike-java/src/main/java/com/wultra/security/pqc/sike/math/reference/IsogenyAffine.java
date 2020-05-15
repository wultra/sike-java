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
package com.wultra.security.pqc.sike.math.reference;

import com.wultra.security.pqc.sike.math.Fp2Element;
import com.wultra.security.pqc.sike.math.FpElement;
import com.wultra.security.pqc.sike.math.api.Fp2Point;
import com.wultra.security.pqc.sike.math.api.Isogeny;
import com.wultra.security.pqc.sike.math.api.Montgomery;
import com.wultra.security.pqc.sike.model.EvaluatedCurve;
import com.wultra.security.pqc.sike.model.MontgomeryCurve;
import com.wultra.security.pqc.sike.param.SikeParam;

import java.math.BigInteger;

/**
 * Reference elliptic curve isogeny operations on Montgomery curves with projective coordinates.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class IsogenyAffine implements Isogeny {

    private final Montgomery montgomery = new MontgomeryAffine();

    @Override
    public MontgomeryCurve curve2Iso(MontgomeryCurve curve, Fp2Point p2) {
        Fp2Element t1, aAp, bAp;
        t1 = p2.getX().square();
        t1 = t1.add(t1);
        t1 = Fp2Element.one(curve.getSikeParam().getPrime()).subtract(t1);
        aAp = t1.add(t1);
        bAp = p2.getX().multiply(curve.getB());
        return new MontgomeryCurve(curve.getSikeParam(), aAp, bAp);
    }

    @Override
    public MontgomeryCurve curve3Iso(MontgomeryCurve curve, Fp2Point p3) {
        Fp2Element t1, t2, aAp, bAp;
        t1 = p3.getX().square();
        bAp = curve.getB().multiply(t1);
        t1 = t1.add(t1);
        t2 = t1.add(t1);
        t1 = t1.add(t2);
        t2 = Fp2Element.generate(curve.getSikeParam().getPrime(), 6);
        t1 = t1.subtract(t2);
        t2 = curve.getA().multiply(p3.getX());
        t1 = t2.subtract(t1);
        aAp = t1.multiply(p3.getX());
        return new MontgomeryCurve(curve.getSikeParam(), aAp, bAp);
    }

    @Override
    public MontgomeryCurve curve4Iso(MontgomeryCurve curve, Fp2Point p4) {
        Fp2Element t1, t2, aAp, bAp;
        t1 = p4.getX().square();
        aAp = t1.square();
        aAp = aAp.add(aAp);
        aAp = aAp.add(aAp);
        t2 = Fp2Element.generate(curve.getSikeParam().getPrime(), 2);
        aAp = aAp.subtract(t2);
        t1 = p4.getX().multiply(t1);
        t1 = t1.add(p4.getX());
        t1 = t1.multiply(curve.getB());
        t2 = t2.inverse();
        t2 = t2.negate();
        bAp = t2.multiply(t1);
        return new MontgomeryCurve(curve.getSikeParam(), aAp, bAp);
    }

    @Override
    public Fp2Point eval2Iso(Fp2Point q, Fp2Point p2) {
        Fp2Element t1, t2, t3, qxAp, qyAp;
        t1 = q.getX().multiply(p2.getX());
        t2 = q.getX().multiply(t1);
        t3 = t1.multiply(p2.getX());
        t3 = t3.add(t3);
        t3 = t2.subtract(t3);
        t3 = t3.add(p2.getX());
        t3 = q.getY().multiply(t3);
        t2 = t2.subtract(q.getX());
        t1 = q.getX().subtract(p2.getX());
        t1 = t1.inverse();
        qxAp = t2.multiply(t1);
        t1 = t1.square();
        qyAp = t3.multiply(t1);
        return new Fp2PointAffine(qxAp, qyAp);
    }

    @Override
    public Fp2Point eval3Iso(BigInteger prime, Fp2Point q, Fp2Point p3) {
        Fp2Element t1, t2, t3, t4, qxAp, qyAp;
        t1 = q.getX().square();
        t1 = t1.multiply(p3.getX());
        t2 = p3.getX().square();
        t2 = q.getX().multiply(t2);
        t3 = t2.add(t2);
        t2 = t2.add(t3);
        t1 = t1.subtract(t2);
        t1 = t1.add(q.getX());
        t1 = t1.add(p3.getX());
        t2 = q.getX().subtract(p3.getX());
        t2 = t2.inverse();
        t3 = t2.square();
        t2 = t2.multiply(t3);
        t4 = q.getX().multiply(p3.getX());
        t4 = t4.subtract(Fp2Element.one(prime));
        t1 = t4.multiply(t1);
        t1 = t1.multiply(t2);
        t2 = t4.square();
        t2 = t2.multiply(t3);
        qxAp = q.getX().multiply(t2);
        qyAp = q.getY().multiply(t1);
        return new Fp2PointAffine(qxAp, qyAp);
    }

    @Override
    public Fp2Point eval4Iso(BigInteger prime, Fp2Point q, Fp2Point p4) {
        Fp2Element t1, t2, t3, t4, t5, qxAp, qyAp;
        t1 = q.getX().square();
        t2 = t1.square();
        t3 = p4.getX().square();
        t4 = t2.multiply(t3);
        t2 = t2.add(t4);
        t4 = t1.multiply(t3);
        t4 = t4.add(t4);
        t5 = t4.add(t4);
        t5 = t5.add(t5);
        t4 = t4.add(t5);
        t2 = t2.add(t4);
        t4 = t3.square();
        t5 = t1.multiply(t4);
        t5 = t5.add(t5);
        t2 = t2.add(t5);
        t1 = t1.multiply(q.getX());
        t4 = p4.getX().multiply(t3);
        t5 = t1.multiply(t4);
        t5 = t5.add(t5);
        t5 = t5.add(t5);
        t2 = t2.subtract(t5);
        t1 = t1.multiply(p4.getX());
        t1 = t1.add(t1);
        t1 = t1.add(t1);
        t1 = t2.subtract(t1);
        t2 = q.getX().multiply(t4);
        t2 = t2.add(t2);
        t2 = t2.add(t2);
        t1 = t1.subtract(t2);
        t1 = t1.add(t3);
        t1 = t1.add(Fp2Element.one(prime));
        t2 = q.getX().multiply(p4.getX());
        t4 = t2.subtract(Fp2Element.one(prime));
        t2 = t2.add(t2);
        t5 = t2.add(t2);
        t1 = t1.subtract(t5);
        t1 = t4.multiply(t1);
        t1 = t3.multiply(t1);
        t1 = q.getY().multiply(t1);
        t1 = t1.add(t1);
        qyAp = t1.negate();
        t2 = t2.subtract(t3);
        t1 = t2.subtract(Fp2Element.one(prime));
        t2 = q.getX().subtract(p4.getX());
        t1 = t2.multiply(t1);
        t5 = t1.square();
        t5 = t5.multiply(t2);
        t5 = t5.inverse();
        qyAp = qyAp.multiply(t5);
        t1 = t1.multiply(t2);
        t1 = t1.inverse();
        t4 = t4.square();
        t1 = t1.multiply(t4);
        t1 = q.getX().multiply(t1);
        t2 = q.getX().multiply(t3);
        t2 = t2.add(q.getX());
        t3 = p4.getX().add(p4.getX());
        t2 = t2.subtract(t3);
        t2 = t2.negate();
        qxAp = t1.multiply(t2);
        return new Fp2PointAffine(qxAp, qyAp);
    }

    @Override
    public EvaluatedCurve iso2e(MontgomeryCurve curve, Fp2Point s) {
        return iso2e(curve, s, null, null);
    }

    @Override
    public EvaluatedCurve iso2e(MontgomeryCurve curve, Fp2Point s, Fp2Point p, Fp2Point q) {
        MontgomeryCurve curveAp = curve;
        Fp2Point sAp = s, pAp = p, qAp = q;
        Fp2Point t;
        int eAp = curve.getSikeParam().getEA();
        if (eAp % 2 == 1) {
            t = montgomery.xDble(curveAp, sAp, eAp - 1);
            curveAp = curve2Iso(curveAp, t);
            if (p != null) {
                pAp = eval2Iso(pAp, t);
            }
            if (q != null) {
                qAp = eval2Iso(qAp, t);
            }
            eAp--;
        }
        for (int e = eAp - 2; e >= 0; e -= 2) {
            t = montgomery.xDble(curveAp, sAp, e);
            curveAp = curve4Iso(curveAp, t);
            // Fix division by zero in reference implementation
            if (e > 0) {
                sAp = eval4Iso(curveAp.getSikeParam().getPrime(), sAp, t);
            }
            if (p != null) {
                pAp = eval4Iso(curveAp.getSikeParam().getPrime(), pAp, t);
            }
            if (q != null) {
                qAp = eval4Iso(curveAp.getSikeParam().getPrime(), qAp, t);
            }
        }
        return new EvaluatedCurve(curveAp, pAp, qAp);
    }

    @Override
    public EvaluatedCurve iso3e(MontgomeryCurve curve, Fp2Point s) {
        return iso3e(curve, s, null, null);
    }

    @Override
    public EvaluatedCurve iso3e(MontgomeryCurve curve, Fp2Point s, Fp2Point p, Fp2Point q) {
        MontgomeryCurve curveAp = curve;
        Fp2Point sAp = s, pAp = p, qAp = q;
        Fp2Point t;
        for (int e = curve.getSikeParam().getEB() - 1; e >= 0; e--) {
            t = montgomery.xTple(curveAp, sAp, e);
            curveAp = curve3Iso(curveAp, t);
            // Fix division by zero in reference implementation
            if (e > 0) {
                sAp = eval3Iso(curveAp.getSikeParam().getPrime(), sAp, t);
            }
            if (p != null) {
                pAp = eval3Iso(curveAp.getSikeParam().getPrime(), pAp, t);
            }
            if (q != null) {
                qAp = eval3Iso(curveAp.getSikeParam().getPrime(), qAp, t);
            }
        }
        return new EvaluatedCurve(curveAp, pAp, qAp);
    }

    @Override
    public Fp2Element isoEx2(SikeParam sikeParam, FpElement sk2, Fp2Element p2, Fp2Element q2, Fp2Element r2) {
        EvaluatedCurve iso = montgomery.getYpYqAB(sikeParam, p2, q2, r2);
        MontgomeryCurve curve = iso.getCurve();
        Fp2Point s = montgomery.doubleAndAdd(curve, sk2.getX(), iso.getQ(), sikeParam.getMsbA());
        s = montgomery.xAdd(curve, iso.getP(), s);
        EvaluatedCurve iso2 = iso2e(curve, s);
        return montgomery.jInv(iso2.getCurve());
    }

    @Override
    public Fp2Element isoEx3(SikeParam sikeParam, FpElement sk3, Fp2Element p3, Fp2Element q3, Fp2Element r3) {
        EvaluatedCurve iso = montgomery.getYpYqAB(sikeParam, p3, q3, r3);
        MontgomeryCurve curve = iso.getCurve();
        Fp2Point s = montgomery.doubleAndAdd(curve, sk3.getX(), iso.getQ(), sikeParam.getMsbB() - 1);
        s = montgomery.xAdd(curve, iso.getP(), s);
        EvaluatedCurve iso3 = iso3e(curve, s);
        return montgomery.jInv(iso3.getCurve());
    }

}
