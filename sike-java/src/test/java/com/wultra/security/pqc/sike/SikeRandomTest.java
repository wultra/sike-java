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
import com.wultra.security.pqc.sike.crypto.Sike;
import com.wultra.security.pqc.sike.model.EncapsulationResult;
import com.wultra.security.pqc.sike.model.EncryptedMessage;
import com.wultra.security.pqc.sike.model.ImplementationType;
import com.wultra.security.pqc.sike.model.Party;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.param.SikeParamP434;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test of SIKE key encapsulation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SikeRandomTest {

    private Sike sike;
    private SikeParam sikeParam;
    private KeyPair keyPair;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void initSike() throws GeneralSecurityException {
        sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        KeyGenerator keyGenerator = new KeyGenerator(sikeParam);
        sike = new Sike(sikeParam);
        System.out.println("Prime: " + sikeParam.getPrime());
        // Enable key decapsulation
        keyPair = keyGenerator.generateKeyPair(Party.BOB);
        System.out.println("Bob's keypair:");
        System.out.println("Private key: " + keyPair.getPrivate());
        System.out.println("Public key: " + keyPair.getPublic());
    }

    @Test
    public void testSikeEncryption() throws GeneralSecurityException {
        System.out.println("----------------------------------------");
        initSike();
        System.out.println("Testing SIKE encryption/decryption");
        byte[] message = "test123456789012".getBytes();
        System.out.println("Message to encrypt: " + new String(message));
        EncryptedMessage encrypted = sike.encrypt(keyPair.getPublic(), message);
        // Encrypted message is sent to Bob
        byte[] decrypted = sike.decrypt(keyPair.getPrivate(), encrypted);
        System.out.println("Decrypted message: " + new String(decrypted));
        boolean match = Arrays.equals(message, decrypted);
        System.out.println("Messages match: " + match);
        assertTrue(match, "Messages do not match");
    }

    @Test
    public void testSikeEncapsulation() throws GeneralSecurityException {
        System.out.println("----------------------------------------");
        initSike();
        System.out.println("Testing SIKE encapsulation/decapsulation");
        EncapsulationResult encapsulationResult = sike.encapsulate(keyPair.getPublic());
        System.out.println("Alice's shared secret: " + new String(Base64.encode(encapsulationResult.getSecret())));
        // Encrypted message is sent to Bob
        EncryptedMessage encrypted = encapsulationResult.getEncryptedMessage();
        byte[] secretDecaps = sike.decapsulate(keyPair.getPrivate(), keyPair.getPublic(), encrypted);
        System.out.println("Bob's shared secret:   " + new String(Base64.encode(secretDecaps)));
        boolean match = Arrays.equals(encapsulationResult.getSecret(), secretDecaps);
        System.out.println("Shared secrets match: " + match);
        assertTrue(match, "Decapsulation failed");
    }

    @Test
    public void testSikeEncapsulationWithMessageTransport() throws GeneralSecurityException {
        System.out.println("----------------------------------------");
        initSike();
        System.out.println("Testing SIKE encapsulation/decapsulation with message transport");
        EncapsulationResult encapsulationResult = sike.encapsulate(keyPair.getPublic());
        System.out.println("Alice's shared secret: " + new String(Base64.encode(encapsulationResult.getSecret())));
        // Encrypted message is sent to Bob
        EncryptedMessage encrypted = encapsulationResult.getEncryptedMessage();
        byte[] encodedMessage = encrypted.getEncoded();
        // Message is transported over network
        EncryptedMessage transported = new EncryptedMessage(sikeParam, encodedMessage);
        byte[] secretDecaps = sike.decapsulate(keyPair.getPrivate(), keyPair.getPublic(), transported);
        System.out.println("Bob's shared secret:   " + new String(Base64.encode(secretDecaps)));
        boolean match = Arrays.equals(encapsulationResult.getSecret(), secretDecaps);
        System.out.println("Shared secrets match: " + match);
        assertTrue(match, "Decapsulation failed");
    }

}
