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
package com.wultra.security.pqc.sike.model;

import com.wultra.security.pqc.sike.math.Fp2Element;
import com.wultra.security.pqc.sike.param.SikeParam;

import java.util.Objects;

/**
 * Montgomery curve paramters.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class MontgomeryCurve {

    private final SikeParam sikeParam;
    private final Fp2Element a;
    private final Fp2Element b;

    /**
     * Montgomery curve constructor.
     * @param sikeParam SIKE parameters.
     * @param a Montgomery curve coefficient a.
     * @param b Montgomery curve coefficient b.
     */
    public MontgomeryCurve(SikeParam sikeParam, Fp2Element a, Fp2Element b) {
        this.sikeParam = sikeParam;
        this.a = a;
        this.b = b;
    }

    /**
     * Get SIKE parameters.
     * @return SIKE parameters.
     */
    public SikeParam getSikeParam() {
        return sikeParam;
    }

    /**
     * Get Montgomery curve coefficient a.
     * @return Montgomery curve coefficient a.
     */
    public Fp2Element getA() {
        return a;
    }

    /**
     * Get Montgomery curve coefficient b.
     * @return Montgomery curve coefficient b.
     */
    public Fp2Element getB() {
        return b;
    }

    @Override
    public String toString() {
        return "p = " + sikeParam.getPrime() + ", a = " + a + ", b = " + b;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MontgomeryCurve that = (MontgomeryCurve) o;
        return a.equals(that.a) &&
                b.equals(that.b);
    }

    @Override
    public int hashCode() {
        return Objects.hash(a, b);
    }
}
