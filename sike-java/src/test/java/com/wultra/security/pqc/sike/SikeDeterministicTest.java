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
import com.wultra.security.pqc.sike.crypto.RandomGenerator;
import com.wultra.security.pqc.sike.crypto.Sike;
import com.wultra.security.pqc.sike.kat.util.CrtDrbgRandom;
import com.wultra.security.pqc.sike.model.*;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.param.SikeParamP434;
import com.wultra.security.pqc.sike.util.OctetEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test of randomness using seed provided to a CRT DRBG random generator in a known SIKE decapsulation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SikeDeterministicTest {

    private static final String SEED = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testDeterministicSike() throws GeneralSecurityException {
        System.out.println("----------------------------------------");
        SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
        System.out.println("Prime: " + sikeParam.getPrime());
        byte[] seedBytes = DatatypeConverter.parseHexBinary(SEED);
        CrtDrbgRandom drbgRandom = new CrtDrbgRandom(seedBytes);
        KeyGenerator keyGenerator = new KeyGenerator(sikeParam, new RandomGenerator(drbgRandom));
        KeyPair keyPair = keyGenerator.generateKeyPair(Party.BOB);
        SidhPrivateKey priv = (SidhPrivateKey) keyPair.getPrivate();
        SidhPublicKey pub = (SidhPublicKey) keyPair.getPublic();
        assertEquals("7C9935A0B07694AA0C6D10E4DB6B1ADD91282214654CB55E7C2CACD53919604D5BAC7B23EEF4B315FEEF5E01", priv.toOctetString());
        assertEquals("4484D7AADB44B40CC180DC568B2C142A60E6E2863F5988614A6215254B2F5F6F79B48F329AD1A2DED20B7ABAB10F7DBF59C3E20B59A700093060D2A44ACDC0083A53CF0808E0B3A827C45176BEE0DC6EC7CC16461E38461C12451BB95191407C1E942BB50D4C7B25A49C644B630159E6C403653838E689FBF4A7ADEA693ED0657BA4A724786AF7953F7BA6E15F9BBF9F5007FB711569E72ACAB05D3463A458536CAB647F00C205D27D5311B2A5113D4B26548000DB237515931A040804E769361F94FF0167C78353D2630A1E6F595A1F80E87F6A5BCD679D7A64C5006F6191D4ADEFA1EA67F6388B7017D453F4FE2DFE80CCC709000B52175BFC3ADE52ECCB0CEBE1654F89D39131C357EACB61E5F13C80AB0165B7714D6BE6DF65F8DE73FF47B7F3304639F0903653ECCFA252F6E2104C4ABAD3C33AF24FD0E56F58DB92CC66859766035419AB2DF600", pub.toOctetString());

        Sike sike = new Sike(sikeParam, drbgRandom);
        EncapsulationResult encapsulationResult = sike.encapsulate(keyPair.getPublic());
        EncryptedMessage encrypted = encapsulationResult.getEncryptedMessage();
        System.out.println("Alice's shared secret: " + new String(Base64.encode(encapsulationResult.getSecret())));

        SidhPublicKey c0 = (SidhPublicKey) encrypted.getC0();
        byte[] c1 = encrypted.getC1();
        assertEquals("0FDEB26DBD96E0CD272283CA5BDD1435BC9A7F9AB7FC24F83CA926DEED038AE4E47F39F9886E0BD7EEBEAACD12AB435CC92AA3383B2C01E6B9E02BC3BEF9C6C2719014562A96A0F3E784E3FA44E5C62ED8CEA79E1108B6FECD5BF8836BF2DAE9FEB1863C4C8B3429220E2797F601FB4B8EBAFDD4F17355508D259CA60721D167F6E5480B5133E824F76D3240E97F31325DBB9A53E9A3EEE2E0712734825615A027857E2000D4D00E11988499A738452C93DA895BFA0E10294895CCF25E3C261CBE38F5D7E19ABE4E322094CB8DEC5BF7484902BABDE33CC69595F6013B20AABA9698C1DEA2BC6F65D57519294E6FEEA3B549599D480948374D2D21B643573C276E1A5B0745301F648D7982AB46A3065639960182BF365819EFC0D4E61E87D2820DBC0E849E99E875B21501D1CA7588A1D458CD70C7DF793D4993B9B1679886CAE8013A8DD854F010A100", c0.toOctetString());
        assertEquals("C9933FA642DC0AEA9985786ED36B98D3", OctetEncoding.toOctetString(c1, 16));

        byte[] secretDecaps = sike.decapsulate(keyPair.getPrivate(), keyPair.getPublic(), encrypted);
        System.out.println("Bob's shared secret:   " + new String(Base64.encode(secretDecaps)));
        assertEquals("35F7F8FF388714DEDC41F139078CEDC9", OctetEncoding.toOctetString(secretDecaps, 16));

        boolean match = Arrays.equals(encapsulationResult.getSecret(), secretDecaps);
        System.out.println("Shared secrets match: " + match);
        assertTrue(match, "Decapsulation failed");
    }

}
