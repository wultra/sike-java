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
