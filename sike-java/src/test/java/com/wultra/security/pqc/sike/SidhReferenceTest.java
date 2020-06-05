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
import com.wultra.security.pqc.sike.crypto.Sidh;
import com.wultra.security.pqc.sike.math.Fp2Element;
import com.wultra.security.pqc.sike.model.ImplementationType;
import com.wultra.security.pqc.sike.model.Party;
import com.wultra.security.pqc.sike.model.SidhPrivateKey;
import com.wultra.security.pqc.sike.model.SidhPublicKey;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.param.SikeParamP434;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.*;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test of SIDH key exchange.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SidhReferenceTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSidhReferenceVsOptimized() throws GeneralSecurityException {
        SikeParam sikeParamReference = new SikeParamP434(ImplementationType.REFERENCE);
        SikeParam sikeParamOptimized = new SikeParamP434(ImplementationType.OPTIMIZED);
        System.out.println("Prime: " + sikeParamReference.getPrime());
        KeyGenerator keyGenerator = new KeyGenerator(sikeParamReference);
        Sidh sidhReference = new Sidh(sikeParamReference);
        Sidh sidhOptimized = new Sidh(sikeParamOptimized);
        System.out.println("----------------------------------------");
        KeyPair keyPairA = keyGenerator.generateKeyPair(Party.ALICE);
        System.out.println("Alice's keypair:");
        System.out.println("Private key: " + keyPairA.getPrivate());
        System.out.println("Public key: " + keyPairA.getPublic());

        KeyPair keyPairB = keyGenerator.generateKeyPair(Party.BOB);
        System.out.println("Bob's keypair:");
        System.out.println("Private key: " + keyPairB.getPrivate());
        System.out.println("Public key: " + keyPairB.getPublic());

        // Bob's public key is sent to Alice (reference)
        Fp2Element secretARef = sidhReference.generateSharedSecret(Party.ALICE, keyPairA.getPrivate(), keyPairB.getPublic());
        System.out.println("Shared secret generated by Alice (reference): " + secretARef);

        // Alice's public key is sent to Bob (reference)
        Fp2Element secretBRef = sidhReference.generateSharedSecret(Party.BOB, keyPairB.getPrivate(), keyPairA.getPublic());
        System.out.println("Shared secret generated by Bob (reference):   " + secretBRef);

        PrivateKey privA = new SidhPrivateKey(sikeParamOptimized, Party.ALICE, keyPairA.getPrivate().getEncoded());
        PublicKey pubA = new SidhPublicKey(sikeParamOptimized, keyPairA.getPublic().getEncoded());
        PrivateKey privB = new SidhPrivateKey(sikeParamOptimized, Party.BOB, keyPairB.getPrivate().getEncoded());
        PublicKey pubB = new SidhPublicKey(sikeParamOptimized, keyPairB.getPublic().getEncoded());

        // Bob's public key is sent to Alice (optimized)
        Fp2Element secretAOpti = sidhOptimized.generateSharedSecret(Party.ALICE, privA, pubB);
        System.out.println("Shared secret generated by Alice (optimized): " + secretAOpti);

        // Alice's public key is sent to Bob (optimized)
        Fp2Element secretBOpti = sidhReference.generateSharedSecret(Party.BOB, privB, pubA);
        System.out.println("Shared secret generated by Bob (optimized):   " + secretBOpti);

        boolean matchRef = secretARef.equals(secretBRef);
        System.out.println("Secrets match (reference): " + matchRef);
        assertTrue(matchRef, "Secrets do not match");

        boolean matchOpti = secretBRef.equals(secretBOpti);
        System.out.println("Secrets match (optimized): " + matchOpti);
        assertTrue(matchOpti, "Secrets do not match");

        boolean match1 = secretARef.equals(secretAOpti);
        System.out.println("Secrets match (optimized): " + match1);
        assertTrue(match1, "Secrets do not match");

        boolean match2 = secretBRef.equals(secretBOpti);
        System.out.println("Secrets match (optimized): " + match2);
        assertTrue(match2, "Secrets do not match");
    }
}