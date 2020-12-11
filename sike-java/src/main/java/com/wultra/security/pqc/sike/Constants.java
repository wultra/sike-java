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

/**
 * Constants class that holds all project's constants
 *
 * @author Kastriot Sahiti, contact@adron.ch
 */
public class Constants {

    private Constants() {

    }

    public static class Exceptions {
        public static final String INVALID_PUBLIC_KEY = "Invalid public key";
        public static final String INVALID_PRIVATE_KEY = "Invalid private key";
        public static final String INVALID_C0 = "Invalid parameter C0";
        public static final String INVALID_C1 = "Invalid parameter C1";
        public static final String INVALID_MESSAGE = "Invalid message";
        public static final String INVALID_PARTY = "Invalid party";
        public static final String INVALID_PRIVATE_KEY_DECAPSULATION = "Private key cannot be used for decapsulation";
        public static final String INVALID_POINT_COORDINATE = "Invalid point coordinate";
        public static final String INVALID_SIKE_PARAM = "Invalid parameter sikeParam";
        public static final String INVALID_BYTES_PARAM = "Invalid parameter bytes";
        public static final String INVALID_IMPLEMENTATION_TYPE = "Invalid implementation type";
        public static final String INVALID_SECRET = "Invalid secret";
        public static final String INVALID_OCTET_STRING = "Invalid octet string";

        public static final String NOT_IMPLEMENTED = "Not implemented yet";
        public static final String UNSUPPORTED_IMPLEMENTATION = "Unsupported implementation type";
        public static final String NULL_ENCRYPTED_MESSAGE = "Encrypted message is null";

        public static final String NEGATIVE_EXPONENT = "Negative exponent";
        public static final String NUMBER_TOO_LARGE = "Number is too large";
        public static final String NEGATIVE_NUMBER = "Number is negative";

        private Exceptions() {

        }
    }
}
