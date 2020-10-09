/*
 * Copyright 2020 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General License for more details.
 *
 * You should have received a copy of the GNU Affero General License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.wultra.security.pqc.sike.param;

import com.wultra.security.pqc.sike.math.api.*;
import com.wultra.security.pqc.sike.math.optimized.fp.FpElementOpti;
import com.wultra.security.pqc.sike.model.ImplementationType;

import java.math.BigInteger;

/**
 * SIKE parameters.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface SikeParam {

    /**
     * Get implementation type.
     * @return Implementation type.
     */
    ImplementationType getImplementationType();

    Fp2ElementFactory getFp2ElementFactory();

    /**
     * Get Montgomery curve math algorithms.
     * @return Montgomery curve math algorithms.
     */
    Montgomery getMontgomery();

    /**
     * Get Isogeny curve algorithms.
     * @return Isogeny curve algorithms.
     */
    Isogeny getIsogeny();

    /**
     * Get SIKE variant name.
     * @return SIKE variant name.
     */
    String getName();

    /**
     * Get Montgomery coefficient a for starting curve.
     * @return Montgomery coefficient a for starting curve.
     */
    Fp2Element getA();

    /**
     * Get Montgomery coefficient b for starting curve.
     * @return Montgomery coefficient b for starting curve.
     */
    Fp2Element getB();

    /**
     * Get parameter eA.
     * @return Parameter eA.
     */
    int getEA();

    /**
     * Get parameter eB.
     * @return Parameter eB.
     */
    int getEB();

    /**
     * Get factor of A.
     * @return Factor of A.
     */
    BigInteger getOrdA();

    /**
     * Get factor of B.
     * @return Factor of b.
     */
    BigInteger getOrdB();

    /**
     * Get most significant bit of A.
     * @return Most significant bit of A.
     */
    int getMsbA();

    /**
     * Get most significant bit of B.
     * @return Most significant bit of B.
     */
    int getMsbB();

    /**
     * Get field prime.
     * @return Field prime.
     */
    BigInteger getPrime();

    /**
     * Get point PA.
     * @return point PA.
     */
    Fp2Point getPA();

    /**
     * Get point QA.
     * @return point QA.
     */
    Fp2Point getQA();

    /**
     * Get point RA.
     * @return point RA.
     */
    Fp2Point getRA();

    /**
     * Get point PB.
     * @return point PB.
     */
    Fp2Point getPB();

    /**
     * Get point QB.
     * @return point QB.
     */
    Fp2Point getQB();

    /**
     * Get point RB.
     * @return point RB.
     */
    Fp2Point getRB();

    /**
     * Get the number of bytes used for cryptography operations.
     * @return Number of bytes used for cryptography operations.
     */
    int getCryptoBytes();

    /**
     * Get the number of bytes used for message operations.
     * @return Number of bytes used for message operations.
     */
    int getMessageBytes();

    /**
     * Get number of rows for optimized tree computations in the 2-isogeny graph.
     * @return Number of rows for optimized tree computations in the 2-isogeny graph.
     */
    int getTreeRowsA();

    /**
     * Get number of rows for optimized tree computations in the 3-isogeny graph.
     * @return Number of rows for optimized tree computations in the 3-isogeny graph.
     */
    int getTreeRowsB();

    /**
     * Get maximum number of points for optimized tree computations in the 2-isogeny graph.
     * @return Maxim number of points for optimized tree computations in the 2-isogeny graph.
     */
    int getTreePointsA();

    /**
     * Get maximum number of points for optimized tree computations in the 3-isogeny graph.
     * @return Maxim number of points for optimized tree computations in the 3-isogeny graph.
     */
    int getTreePointsB();

    /**
     * Get optimization strategy for tree computations in the 2-isogeny graph.
     * @return Optimization strategy for tree computations in the 2-isogeny graph.
     */
    int[] getStrategyA();

    /**
     * Get optimization strategy for tree computations in the 3-isogeny graph.
     * @return Optimization strategy for tree computations in the 3-isogeny graph.
     */
    int[] getStrategyB();

    int getFpWords();

    int getZeroWords();

    FpElementOpti getP();

    FpElementOpti getP1();

    FpElementOpti getPx2();

    FpElementOpti getPR2();

    int[] getPowStrategy();

    int[] getMulStrategy();

    int getInitialMul();

}
