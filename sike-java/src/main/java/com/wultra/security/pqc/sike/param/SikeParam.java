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
package com.wultra.security.pqc.sike.param;

import com.wultra.security.pqc.sike.math.*;
import com.wultra.security.pqc.sike.math.api.Fp2Point;
import com.wultra.security.pqc.sike.math.api.Isogeny;
import com.wultra.security.pqc.sike.math.api.Montgomery;
import com.wultra.security.pqc.sike.math.optimized.MontgomeryProjective;
import com.wultra.security.pqc.sike.math.reference.Fp2PointAffine;
import com.wultra.security.pqc.sike.math.reference.IsogenyAffine;
import com.wultra.security.pqc.sike.math.reference.MontgomeryAffine;
import com.wultra.security.pqc.sike.model.ImplementationType;

import java.math.BigInteger;

/**
 * SIKE parameters.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SikeParam {

    private final Montgomery montgomery;
    private final Isogeny isogeny;

    private String name;
    private Fp2Element a;
    private Fp2Element b;
    private int ea;
    private int eb;
    private BigInteger prime;
    private Fp2Point pa;
    private Fp2Point qa;
    private Fp2Point pb;
    private Fp2Point qb;
    private int cryptoBytes;
    private int messageBytes;

    /**
     * Constructor of SIKE parameters.
     * @param name SIKE variant name.
     * @param implementationType Implementation type.
     */
    public SikeParam(String name, ImplementationType implementationType) {
        if (implementationType == ImplementationType.REFERENCE) {
            montgomery = new MontgomeryAffine();
            isogeny = new IsogenyAffine();
        } else if (implementationType == ImplementationType.OPTIMIZED) {
            montgomery = new MontgomeryProjective();
            isogeny = new IsogenyAffine();
        } else {
            throw new IllegalArgumentException("Unsupported implementation type: " + implementationType);
        }
        // TODO - add SIKEp503, SIKEp610 and SIKEp751 parameters and all optimized parameters
        switch (name) {
            case "SIKEp434":
                initSikeP434();
                return;
        }
        throw new IllegalArgumentException("Unsupported SIKE variant: " + name);
    }

    /**
     * Get Montgomery curve math algorithms.
     * @return Montgomery curve math algorithms.
     */
    public Montgomery getMontgomery() {
        return montgomery;
    }

    /**
     * Get Isogeny curve algorithms.
     * @return Isogeny curve algorithms.
     */
    public Isogeny getIsogeny() {
        return isogeny;
    }

    /**
     * Get SIKE variant name.
     * @return SIKE variant name.
     */
    public String getName() {
        return name;
    }

    /**
     * Get Montgomery coefficient a for starting curve.
     * @return Montgomery coefficient a for starting curve.
     */
    public Fp2Element getA() {
        return a;
    }

    /**
     * Get Montgomery coefficient b for starting curve.
     * @return Montgomery coefficient b for starting curve.
     */
    public Fp2Element getB() {
        return b;
    }

    /**
     * Get parameter EA.
     * @return Parameter EA.
     */
    public int getEA() {
        return ea;
    }

    /**
     * Get parameter EB.
     * @return Parameter EB.
     */
    public int getEB() {
        return eb;
    }

    /**
     * Get field prime.
     * @return Field prime.
     */
    public BigInteger getPrime() {
        return prime;
    }

    /**
     * Get public point PA.
     * @return Public point PA.
     */
    public Fp2Point getPA() {
        return pa;
    }

    /**
     * Get public point QA.
     * @return Public point QA.
     */
    public Fp2Point getQA() {
        return qa;
    }

    /**
     * Get public point PB.
     * @return Public point PB.
     */
    public Fp2Point getPB() {
        return pb;
    }

    /**
     * Get public point QB.
     * @return Public point QB.
     */
    public Fp2Point getQB() {
        return qb;
    }

    /**
     * Get the number of bytes used for cryptography operations.
     * @return Number of bytes used for cryptography operations.
     */
    public int getCryptoBytes() {
        return cryptoBytes;
    }

    /**
     * Get the number of bytes used for message operations.
     * @return Number of bytes used for message operations.
     */
    public int getMessageBytes() {
        return messageBytes;
    }

    /**
     * Initialize variant SIKEp434.
     */
    private void initSikeP434() {
        // EA = 216, EB = 137
        int FIELD_PRIME_PARAM_EA = 216;
        int FIELD_PRIME_PARAM_EB = 137;
        BigInteger FIELD_PRIME = new BigInteger("2341F271773446CFC5FD681C520567BC65C783158AEA3FDC1767AE2FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

        // A = 6, B = 1
        Fp2Element PUBLIC_PARAM_ELEMENT_A = Fp2Element.generate(FIELD_PRIME, 6);
        Fp2Element PUBLIC_PARAM_ELEMENT_B = Fp2Element.one(FIELD_PRIME);

        // PA = (100i + 248, 304i + 199) and QA = (426i + 394, 51i + 79)
        FpElement PUBLIC_POINT_PA_X0 = new FpElement(FIELD_PRIME, new BigInteger("3CCFC5E1F050030363E6920A0F7A4C6C71E63DE63A0E6475AF621995705F7C84500CB2BB61E950E19EAB8661D25C4A50ED279646CB48", 16));
        FpElement PUBLIC_POINT_PA_X1 = new FpElement(FIELD_PRIME, new BigInteger("1AD1C1CAE7840EDDA6D8A924520F60E573D3B9DFAC6D189941CB22326D284A8816CC4249410FE80D68047D823C97D705246F869E3EA50", 16));
        FpElement PUBLIC_POINT_PA_Y0 = new FpElement(FIELD_PRIME, new BigInteger("1AB066B84949582E3F66688452B9255E72A017C45B148D719D9A63CDB7BE6F48C812E33B68161D5AB3A0A36906F04A6A6957E6F4FB2E0", 16));
        FpElement PUBLIC_POINT_PA_Y1 = new FpElement(FIELD_PRIME, new BigInteger("FD87F67EA576CE97FF65BF9F4F7688C4C752DCE9F8BD2B36AD66E04249AAF8337C01E6E4E1A844267BA1A1887B433729E1DD90C7DD2F", 16));
        FpElement PUBLIC_POINT_QA_X0 = new FpElement(FIELD_PRIME, new BigInteger("C7461738340EFCF09CE388F666EB38F7F3AFD42DC0B664D9F461F31AA2EDC6B4AB71BD42F4D7C058E13F64B237EF7DDD2ABC0DEB0C6C", 16));
        FpElement PUBLIC_POINT_QA_X1 = new FpElement(FIELD_PRIME, new BigInteger("25DE37157F50D75D320DD0682AB4A67E471586FBC2D31AA32E6957FA2B2614C4CD40A1E27283EAAF4272AE517847197432E2D61C85F5", 16));
        FpElement PUBLIC_POINT_QA_Y0 = new FpElement(FIELD_PRIME, new BigInteger("1D407B70B01E4AEE172EDF491F4EF32144F03F5E054CEF9FDE5A35EFA3642A11817905ED0D4F193F31124264924A5F64EFE14B6EC97E5", 16));
        FpElement PUBLIC_POINT_QA_Y1 = new FpElement(FIELD_PRIME, new BigInteger("E7DEC8C32F50A4E735A839DCDB89FE0763A184C525F7B7D0EBC0E84E9D83E9AC53A572A25D19E1464B509D97272AE761657B4765B3D6", 16));
        Fp2Point PUBLIC_POINT_PA = new Fp2PointAffine(new Fp2Element(FIELD_PRIME, PUBLIC_POINT_PA_X0, PUBLIC_POINT_PA_X1), new Fp2Element(FIELD_PRIME, PUBLIC_POINT_PA_Y0, PUBLIC_POINT_PA_Y1));
        Fp2Point PUBLIC_POINT_QA = new Fp2PointAffine(new Fp2Element(FIELD_PRIME, PUBLIC_POINT_QA_X0, PUBLIC_POINT_QA_X1), new Fp2Element(FIELD_PRIME, PUBLIC_POINT_QA_Y0, PUBLIC_POINT_QA_Y1));

        // PB = (358i + 275, 410i + 104) and QB = (20i + 185, 281i + 239)
        FpElement PUBLIC_POINT_PB_X0 = new FpElement(FIELD_PRIME, new BigInteger("8664865EA7D816F03B31E223C26D406A2C6CD0C3D667466056AAE85895EC37368BFC009DFAFCB3D97E639F65E9E45F46573B0637B7A9", 16));
        FpElement PUBLIC_POINT_PB_X1 = new FpElement(FIELD_PRIME, new BigInteger("0", 16));
        FpElement PUBLIC_POINT_PB_Y0 = new FpElement(FIELD_PRIME, new BigInteger("6AE515593E73976091978DFBD70BDA0DD6BCAEEBFDD4FB1E748DDD9ED3FDCF679726C67A3B2CC12B39805B32B612E058A4280764443B", 16));
        FpElement PUBLIC_POINT_PB_Y1 = new FpElement(FIELD_PRIME, new BigInteger("0", 16));
        FpElement PUBLIC_POINT_QB_X0 = new FpElement(FIELD_PRIME, new BigInteger("12E84D7652558E694BF84C1FBDAAF99B83B4266C32EC65B10457BCAF94C63EB063681E8B1E7398C0B241C19B9665FDB9E1406DA3D3846", 16));
        FpElement PUBLIC_POINT_QB_X1 = new FpElement(FIELD_PRIME, new BigInteger("0", 16));
        FpElement PUBLIC_POINT_QB_Y0 = new FpElement(FIELD_PRIME, new BigInteger("0", 16));
        FpElement PUBLIC_POINT_QB_Y1 = new FpElement(FIELD_PRIME, new BigInteger("EBAAA6C731271673BEECE467FD5ED9CC29AB564BDED7BDEAA86DD1E0FDDF399EDCC9B49C829EF53C7D7A35C3A0745D73C424FB4A5FD2", 16));
        Fp2Point PUBLIC_POINT_PB = new Fp2PointAffine(new Fp2Element(FIELD_PRIME, PUBLIC_POINT_PB_X0, PUBLIC_POINT_PB_X1), new Fp2Element(FIELD_PRIME, PUBLIC_POINT_PB_Y0, PUBLIC_POINT_PB_Y1));
        Fp2Point PUBLIC_POINT_QB = new Fp2PointAffine(new Fp2Element(FIELD_PRIME, PUBLIC_POINT_QB_X0, PUBLIC_POINT_QB_X1), new Fp2Element(FIELD_PRIME, PUBLIC_POINT_QB_Y0, PUBLIC_POINT_QB_Y1));

        this.name = "SIKEp434";
        this.a = PUBLIC_PARAM_ELEMENT_A;
        this.b = PUBLIC_PARAM_ELEMENT_B;
        this.ea = FIELD_PRIME_PARAM_EA;
        this.eb = FIELD_PRIME_PARAM_EB;
        this.prime = FIELD_PRIME;
        this.pa = PUBLIC_POINT_PA;
        this.pb = PUBLIC_POINT_PB;
        this.qa = PUBLIC_POINT_QA;
        this.qb = PUBLIC_POINT_QB;
        this.cryptoBytes = 16;
        this.messageBytes = 16;
    }

}
