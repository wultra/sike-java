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
package com.wultra.security.pqc.sike.crypto;

import com.wultra.security.pqc.sike.math.Fp2Element;
import com.wultra.security.pqc.sike.math.api.Isogeny;
import com.wultra.security.pqc.sike.math.api.Montgomery;
import com.wultra.security.pqc.sike.math.api.Fp2Point;
import com.wultra.security.pqc.sike.model.*;
import com.wultra.security.pqc.sike.param.SikeParam;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * SIDH and SIKE key generator.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class KeyGenerator {

    private final Montgomery montgomery;
    private final Isogeny isogeny;
    private final SikeParam sikeParam;

    private final RandomGenerator randomGenerator = new RandomGenerator();

    /**
     * Key generator constructor.
     * @param sikeParam SIKE parameters.
     */
    public KeyGenerator(SikeParam sikeParam) {
        this.sikeParam = sikeParam;
        this.montgomery = sikeParam.getMontgomery();
        this.isogeny = sikeParam.getIsogeny();
    }

    /**
     * Generate a key pair.
     * @param party Alice or Bob.
     * @return Generated key pair.
     */
    public KeyPair generateKeyPair(Party party) {
        return generateKeyPair(party, false);
    }

    /**
     * Generate a key pair.
     * @param party Alice or Bob.
     * @param enableDecaps Whether generated private key is usable for decapsulation in SIKE.
     * @return Generated key pair.
     */
    public KeyPair generateKeyPair(Party party, boolean enableDecaps) {
        PrivateKey privateKey = generatePrivateKey(party, enableDecaps);
        PublicKey publicKey = derivePublicKey(party, privateKey);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Generate a private key.
     * @param party Alice or Bob.
     * @return Generated private key.
     */
    public PrivateKey generatePrivateKey(Party party) {
        return generatePrivateKey(party, false);
    }

    /**
     * Generate a private key.
     * @param party Alice or Bob.
     * @param enableDecaps Whether generated private key is usable for decapsulation in SIKE.
     * @return Generated key pair.
     */
    public PrivateKey generatePrivateKey(Party party, boolean enableDecaps) {
        /* Static key values for testing
        if (party == Party.ALICE) {
            return new SidhPrivateKey(new BigInteger("11"));
        }
        if (party == Party.BOB) {
            return new SidhPrivateKey(new BigInteger("2"));
        }
        return null;
        */
        // TODO - improve key generation algorithm, see reference implementation
        BigInteger randomKey = randomGenerator.generateRandomKey(sikeParam);
        return new SidhPrivateKey(sikeParam, randomKey, enableDecaps);
    }

    /**
     * Derive public key from a private key.
     * @param party Alice or Bob.
     * @param privateKey Private key.
     * @return Derived public key.
     */
    public PublicKey derivePublicKey(Party party, PrivateKey privateKey) {
        if (!(privateKey instanceof SidhPrivateKey)) {
            throw new IllegalArgumentException("Invalid private key");
        }
        SidhPrivateKey priv = (SidhPrivateKey) privateKey;
        MontgomeryCurve curve = new MontgomeryCurve(sikeParam, sikeParam.getA(), sikeParam.getB());
        EvaluatedCurve evaluatedCurve;
        if (party == Party.ALICE) {
            Fp2Point s = montgomery.doubleAndAdd(curve, priv.getKey().getX(), sikeParam.getQA());
            s = montgomery.xAdd(curve, sikeParam.getPA(), s);
            evaluatedCurve = isogeny.iso2e(curve, s, sikeParam.getPB(), sikeParam.getQB());
        } else if (party == Party.BOB) {
            Fp2Point s = montgomery.doubleAndAdd(curve, priv.getKey().getX(), sikeParam.getQB());
            s = montgomery.xAdd(curve, sikeParam.getPB(), s);
            evaluatedCurve = isogeny.iso3e(curve, s, sikeParam.getPA(), sikeParam.getQA());
        } else {
            throw new IllegalArgumentException("Invalid party");
        }
        Fp2Point p = evaluatedCurve.getP();
        Fp2Point q = evaluatedCurve.getQ();
        Fp2Point r = montgomery.getXr(evaluatedCurve.getCurve(), p, q);

        Fp2Element px = new Fp2Element(sikeParam.getPrime(), p.getX().getX0(), p.getX().getX1());
        Fp2Element qx = new Fp2Element(sikeParam.getPrime(), q.getX().getX0(), q.getX().getX1());
        Fp2Element rx = new Fp2Element(sikeParam.getPrime(), r.getX().getX0(), r.getX().getX1());
        return new SidhPublicKey(sikeParam, px, qx, rx);
    }

}
