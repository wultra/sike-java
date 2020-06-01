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
package com.wultra.security.pqc.sike;

import com.wultra.security.pqc.sike.crypto.KeyGenerator;
import com.wultra.security.pqc.sike.model.ImplementationType;
import com.wultra.security.pqc.sike.model.Party;
import com.wultra.security.pqc.sike.model.SidhPrivateKey;
import com.wultra.security.pqc.sike.model.SidhPublicKey;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.param.SikeParamP434;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test of key conversions.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class KeyConversionTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testConversionToByteArray() throws GeneralSecurityException {
        SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        KeyGenerator keyGenerator = new KeyGenerator(sikeParam);
        KeyPair keyPairA = keyGenerator.generateKeyPair(Party.ALICE);
        KeyPair keyPairB = keyGenerator.generateKeyPair(Party.BOB);
        byte[] privKeyBytesA = keyPairA.getPrivate().getEncoded();
        byte[] pubKeyBytesA = keyPairA.getPublic().getEncoded();
        byte[] privKeyBytesB = keyPairB.getPrivate().getEncoded();
        byte[] pubKeyBytesB = keyPairB.getPublic().getEncoded();
        PrivateKey privKeyA = new SidhPrivateKey(sikeParam, Party.ALICE, privKeyBytesA);
        PublicKey pubKeyA = new SidhPublicKey(sikeParam, pubKeyBytesA);
        PrivateKey privKeyB = new SidhPrivateKey(sikeParam, Party.BOB, privKeyBytesB);
        PublicKey pubKeyB = new SidhPublicKey(sikeParam, pubKeyBytesB);
        assertEquals(privKeyA, keyPairA.getPrivate());
        assertEquals(pubKeyA, keyPairA.getPublic());
        assertEquals(privKeyB, keyPairB.getPrivate());
        assertEquals(pubKeyB, keyPairB.getPublic());
    }

    @Test
    public void testConversionToOctets() throws GeneralSecurityException {
        SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        KeyGenerator keyGenerator = new KeyGenerator(sikeParam);
        KeyPair keyPairA = keyGenerator.generateKeyPair(Party.ALICE);
        KeyPair keyPairB = keyGenerator.generateKeyPair(Party.BOB);
        String privKeyBytesA = ((SidhPrivateKey) keyPairA.getPrivate()).toOctetString();
        String pubKeyBytesA = ((SidhPublicKey) keyPairA.getPublic()).toOctetString();
        String privKeyBytesB = ((SidhPrivateKey) keyPairB.getPrivate()).toOctetString();
        String pubKeyBytesB = ((SidhPublicKey) keyPairB.getPublic()).toOctetString();
        PrivateKey privKeyA = new SidhPrivateKey(sikeParam, Party.ALICE, privKeyBytesA);
        PublicKey pubKeyA = new SidhPublicKey(sikeParam, pubKeyBytesA);
        PrivateKey privKeyB = new SidhPrivateKey(sikeParam, Party.BOB, privKeyBytesB);
        PublicKey pubKeyB = new SidhPublicKey(sikeParam, pubKeyBytesB);
        assertEquals(privKeyA, keyPairA.getPrivate());
        assertEquals(pubKeyA, keyPairA.getPublic());
        assertEquals(privKeyB, keyPairB.getPrivate());
        assertEquals(pubKeyB, keyPairB.getPublic());
    }

}
