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
package com.wultra.security.pqc.sike.kat;

import com.wultra.security.pqc.sike.crypto.KeyGenerator;
import com.wultra.security.pqc.sike.crypto.RandomGenerator;
import com.wultra.security.pqc.sike.crypto.Sike;
import com.wultra.security.pqc.sike.kat.model.KatRspFile;
import com.wultra.security.pqc.sike.kat.model.KatRspRecord;
import com.wultra.security.pqc.sike.kat.util.CrtDrbgRandom;
import com.wultra.security.pqc.sike.model.*;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.util.OctetEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test of KAT responses for SIKEp434.
 */
public class KatP434Test {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testKatP434() throws FileNotFoundException, GeneralSecurityException {
        String runAllKatTests = System.getProperty("runAllKatTests");
        boolean runAllTests = false;
        if ("true".equals(runAllKatTests)) {
            runAllTests = true;
        }
        System.out.println("----------------------------------------");
        System.out.println("KAT tests for SIKEp434");
        ClassLoader classLoader = getClass().getClassLoader();
        URL fileName = classLoader.getResource("kat/PCQkemKAT_374.rsp");
        assertNotNull(fileName);
        File file = new File(fileName.getFile());
        KatRspFile katFile = new KatRspFile(file);
        List<KatRspRecord> katRecords = katFile.getKatRecords();

        SikeParam sikeParam = new SikeParam("SIKEp434", ImplementationType.REFERENCE);
        System.out.println("Prime: " + sikeParam.getPrime());

        for (KatRspRecord kat: katRecords) {
            if (!runAllTests && kat.getCount() > 2) {
                System.out.println("Additional tests were skipped, use -DrunAllKatTests=true to run all KAT tests");
                break;
            }
            System.out.println("Record: " + kat.getCount());
            byte[] seedBytes = DatatypeConverter.parseHexBinary(kat.getSeed());
            CrtDrbgRandom drbgRandom = new CrtDrbgRandom(seedBytes);
            KeyGenerator keyGenerator = new KeyGenerator(sikeParam, new RandomGenerator(drbgRandom));
            KeyPair keyPair = keyGenerator.generateKeyPair(Party.BOB);
            SidhPrivateKey priv = (SidhPrivateKey) keyPair.getPrivate();
            SidhPublicKey pub = (SidhPublicKey) keyPair.getPublic();
            assertEquals(kat.getSk(), priv.toOctetString() + pub.toOctetString());
            assertEquals(kat.getPk(), pub.toOctetString());

            Sike sike = new Sike(sikeParam, drbgRandom);
            EncapsulationResult encapsulationResult = sike.encapsulate(keyPair.getPublic());
            EncryptedMessage encrypted = encapsulationResult.getEncryptedMessage();
            SidhPublicKey c0 = (SidhPublicKey) encrypted.getC0();
            String ssA = OctetEncoding.toOctetString(encapsulationResult.getSecret(), 16);
            System.out.println("Alice's shared secret: " + ssA);
            byte[] c1 = encrypted.getC1();
            assertEquals(kat.getCt(), c0.toOctetString() + OctetEncoding.toOctetString(c1, 16));

            byte[] secretDecaps = sike.decapsulate(keyPair.getPrivate(), keyPair.getPublic(), encrypted);
            String ssB = OctetEncoding.toOctetString(secretDecaps, 16);
            System.out.println("Bob's shared secret:   " + ssB);
            assertEquals(kat.getSs(), ssB);

            boolean match = Arrays.equals(encapsulationResult.getSecret(), secretDecaps);
            System.out.println("Shared secrets match: " + match);
            assertTrue(match, "Decapsulation failed");
        }
    }
}
