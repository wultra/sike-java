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

import java.math.BigInteger;
import java.util.Objects;

/**
 * Point with projective coordinates [x:z] in F(p^2).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Fp2PointProjective implements Fp2Point {

    private final Fp2Element x;
    private final Fp2Element z;

    public Fp2PointProjective(Fp2Element x, Fp2Element z) {
        this.x = x;
        this.z = z;
    }

    public static Fp2Point infinity(BigInteger prime) {
        return new Fp2PointProjective(Fp2Element.zero(prime), Fp2Element.zero(prime));
    }

    @Override
    public Fp2Element getX() {
        return x;
    }

    /**
     * The y coordinate is always null in projective coordinate system.
     * @return Null value.
     */
    @Override
    public Fp2Element getY() {
        return null;
    }

    @Override
    public Fp2Element getZ() {
        return z;
    }

    @Override
    public Fp2Point add(Fp2Point o) {
        return new Fp2PointProjective(x.add(o.getX()), z.add(o.getY()));
    }

    @Override
    public Fp2Point subtract(Fp2Point o) {
        return new Fp2PointProjective(x.subtract(o.getX()), z.subtract(o.getY()));
    }

    @Override
    public Fp2Point multiply(Fp2Point o) {
        return new Fp2PointProjective(x.multiply(o.getX()), z.multiply(o.getY()));
    }

    @Override
    public Fp2Point square() {
        return multiply(this);
    }

    @Override
    public Fp2Point inverse() {
        return new Fp2PointProjective(x.inverse(), z.inverse());
    }

    @Override
    public Fp2Point negate() {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public boolean isInfinite() {
        throw new RuntimeException("Not implemented yet");
    }

    public String toString() {
        return "(" + x.toString() + ", " + z.toString() + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Fp2PointProjective that = (Fp2PointProjective) o;
        return x.equals(that.x) &&
                z.equals(that.z);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, z);
    }
}
