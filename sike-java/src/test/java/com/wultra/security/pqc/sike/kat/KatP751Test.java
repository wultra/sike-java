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

import com.wultra.security.pqc.sike.model.ImplementationType;
import com.wultra.security.pqc.sike.param.SikeParam;
import com.wultra.security.pqc.sike.param.SikeParamP751;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.security.GeneralSecurityException;
import java.security.Security;

/**
 * Test of KAT responses for SIKEp710.
 */
class KatP751Test {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testKatP710() throws FileNotFoundException, GeneralSecurityException {
        SikeParam sikeParam = new SikeParamP751(ImplementationType.OPTIMIZED);
        KatTester.run(sikeParam, "kat/PQCkemKAT_644.rsp");
    }
}
