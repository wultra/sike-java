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
import com.wultra.security.pqc.sike.math.api.Fp2Point;
import com.wultra.security.pqc.sike.math.api.Isogeny;
import com.wultra.security.pqc.sike.math.api.Montgomery;
import com.wultra.security.pqc.sike.model.*;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.util.ByteEncoding;

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

    private final RandomGenerator randomGenerator;

    /**
     * Key generator constructor.
     * @param sikeParam SIKE parameters.
     */
    public KeyGenerator(SikeParam sikeParam) {
        this.sikeParam = sikeParam;
        this.montgomery = sikeParam.getMontgomery();
        this.isogeny = sikeParam.getIsogeny();
        this.randomGenerator = new RandomGenerator();
    }

    /**
     * Constructor for key generator with alternative random generator.
     * @param sikeParam SIKE parameters.
     * @param randomGenerator Alternative random generator.
     */
    public KeyGenerator(SikeParam sikeParam, RandomGenerator randomGenerator) {
        this.sikeParam = sikeParam;
        this.montgomery = sikeParam.getMontgomery();
        this.isogeny = sikeParam.getIsogeny();
        this.randomGenerator = randomGenerator;
    }

    /**
     * Generate a key pair.
     * @param party Alice or Bob.
     * @return Generated key pair.
     */
    public KeyPair generateKeyPair(Party party) {
        PrivateKey privateKey = generatePrivateKey(party);
        PublicKey publicKey = derivePublicKey(party, privateKey);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Generate a private key.
     * @param party Alice or Bob.
     * @return Generated key pair.
     */
    public PrivateKey generatePrivateKey(Party party) {
        byte[] s = randomGenerator.generateRandomBytes(16);
        BigInteger randomKey = generateRandomKey(sikeParam, party);
        return new SidhPrivateKey(sikeParam, randomKey, s);
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
            Fp2Point s = montgomery.doubleAndAdd(curve, priv.getKey().getX(), sikeParam.getQA(), sikeParam.getMsbA());
            s = montgomery.xAdd(curve, sikeParam.getPA(), s);
            evaluatedCurve = isogeny.iso2e(curve, s, sikeParam.getPB(), sikeParam.getQB());
        } else if (party == Party.BOB) {
            Fp2Point s = montgomery.doubleAndAdd(curve, priv.getKey().getX(), sikeParam.getQB(), sikeParam.getMsbB() - 1);
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

    /**
     * Generate a random key.
     * @param sikeParam SIKE parameters.
     * @return Random BigInteger usable as a private key.
     */
    private BigInteger generateRandomKey(SikeParam sikeParam, Party party) {
        if (party == Party.ALICE) {
            // random value in [0, 2^EA - 1]
            int length = (sikeParam.getMsbA() + 7) / 8;
            byte[] randomBytes = randomGenerator.generateRandomBytes(length);
            return ByteEncoding.fromByteArray(randomBytes);
        }
        if (party == Party.BOB) {
            // random value in [0, 2^Floor(Log(2,3^EB)) - 1]
            int length = (sikeParam.getMsbB() - 1 + 7) / 8;
            byte[] randomBytes = randomGenerator.generateRandomBytes(length);
            BigInteger modulo = new BigInteger("2").pow(sikeParam.getMsbB() - 1);
            return ByteEncoding.fromByteArray(randomBytes).mod(modulo);
        }
        throw new IllegalArgumentException("Invalid party");
    }

}
