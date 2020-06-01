# SIKE Java Documentation

This documentation describes usage of SIKE Java.

If you are new to SIDH or SIKE, please check out the official resources which provide many educational materials:
- Official SIKE documentation is available at: https://sike.org
- SIKE specification from round 2 NIST submission is available at: https://sike.org/files/SIDH-spec.pdf
- The main concepts are explained nicely in SIKE for beginners: https://eprint.iacr.org/2019/132

## Features

The experimental port of SIKE to Java provides following functionality:
- Key generation
- SIDH key agreement
- SIKE key encryption/decryption
- SIKE key encapsulation/decapsulation

Following SIKE variants are supported:
- SIKEp434
- SIKEp503
- SIKEp610
- SIKEp751

Both reference and optimized implementations have been ported and it is possible to switch the implementation type.
The port currently does not support compressed keys. The field mathematics is based on Java BigInteger 
and the math performance will be further improved in the future by switching to an alternative implementation.

The private and public keys can be exported into:
- Octet representation as defined in SIKE specification.
- Byte array representation for a more optimal encoding.

The keys can be imported from their byte array representation.

The port includes KAT vector tests for all supported SIKE variants.

Note that the aim of this port was not to create a 100% identical port with the C code because the original syntax 
is not object oriented. We also discovered minor issues during the port and reported them to the SIKE developers.
There are minor differences between the C and Java implementations, however given the passing KAT vector tests the
implementations should be 100% compatible.  

## Usage

SIKE Java provides an easy to use interface for generating keys and computing shared secrets.

### Initialization

As the first step, you need to initialize the Bouncy Castle provider:
```java
Security.addProvider(new BouncyCastleProvider());
```

The Bouncy Castle initialization should be done at the application start, before any of the SIKE Java functionality 
is used.

Before generating keys you should choose the variant you want to use. The table below summarizes the available variants:

| SIKE Variant Name | NIST Security Level | Private Key Size | Public Key Size | Shared Secret Size |
| :---------------: | :-----------------: | :--------------: | :-------------: | :----------------: | 
| SIKEp434 | 1 | 374 | 330 | 16 |
| SIKEp503 | 2 | 434 | 378 | 24 |
| SIKEp610 | 3 | 524 | 462 | 24 |
| SIKEp751 | 5 | 644 | 564 | 32 |

Two implementations are available:
 - `REFERENCE` - slow implementation with focus on readability of code 
 - `OPTIMIZED` - fast implementation with focus on performance and security

The selected SIKE parameters need to be created like this: 
```java 
SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
```

### Generating Keys

You can generate key pairs using the `KeyGenerator` class: 
 
```java
KeyGenerator keyGenerator = new KeyGenerator(sikeParam);
```

Before generating a key pair you need to decide whether the party is `ALICE` or `BOB`. 

For SIKE, `ALICE` is the server and `BOB` is the client which initiates the communication.

To generate a key pair for `ALICE`, use:
```java
KeyPair keyPairA = keyGenerator.generateKeyPair(Party.ALICE);
``` 

To generate a key pair for `BOB`, use:
```java
KeyPair keyPairB = keyGenerator.generateKeyPair(Party.BOB);
``` 

You can obtain the keys from the key pair like this:

```java
PrivateKey priv = keyPair.getPrivate();
PrivateKey pub = keyPair.getPrivate();
```

In case you need to export the keys, cast them to `SidhPrivateKey` or `SidhPublicKey` and call either of these methods:
- `getEncoded()` - returns the byte array representation of the key
- `toOctetString()` - converts the key to octet string as defined in SIKE specification

You can also obtain the numeric representation of keys using: 
- `priv.getKey()` - returns the FpElement representing the private key
- `pub.getPx()` - returns the Fp2Element representing the public key element phi(Px)
- `pub.getQx()` - returns the Fp2Element representing the public key element phi(Qx)
- `pub.getRx()` - returns the Fp2Element representing the public key element phi(Rx)

You can obtain the BigInteger representations of the keys using:
- `priv.getM()` - returns the BigInteger representing the private key
- `pub.getPx().getX0().getX()` - returns the BigInteger representing the real part of public key x coordinate phi(Px)
- `pub.getPx().getX1().getX()` - returns the BigInteger representing the imaginary part of public key x coordinate phi(Px)

Obtaining BigInteger representations of x coordinates of phi(Qx) and phi(Rx) is analogous to phi(Px).

You can construct private keys using their byte array representation:
```java
SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
byte[] secret = secretBytes;
PrivateKey priv = new SidhPrivateKey(sikeParam, Party.ALICE, secret);
```

You can also construct private keys using their BigInteger representation:
```java
SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
BigInteger secret = new BigInteger(secretNumber);
PrivateKey priv = new SidhPrivateKey(sikeParam, Party.ALICE, secret);
```

Once you have a private key, you can derive the public key like this:
```java
PublicKey pub = keyGenerator.derivePublicKey(Party.ALICE);
```

### SIDH Key Agreement

Once you initialized the keys for both parties, it is easy to compute the shared secret using SIDH. The process
is the same for both parties, silarly to `DH` or `ECDH` opposite public and private keys are used:
```java
Sidh sidh = new Sidh(sikeParam);
Fp2Element secretA = sidh.generateSharedSecret(Party.ALICE, keyPairA.getPrivate(), keyPairB.getPublic());
Fp2Element secretB = sidh.generateSharedSecret(Party.BOB, keyPairB.getPrivate(), keyPairA.getPublic());
```

You can obtain the byte array representing secret j-invariants of both sides using:

```java
byte[] encoded = secret.getEncoded();
```

Both secrets `secretA` and `secretB` are equal in case the key agreement succeeded. The shared secret sizes 
match the `Fp2Element` sizes in chosen SIKE variant, which is 1/3 of the size of the public key. For obtaining 
shorter shared secret sizes and eliminating any risks related to using BigInteger represenation of the j-invariant,
using a hashing function on the shared secret values is advised.

Note that SIDH provides lower security than SIKE, it is an ind-CPA scheme and should be only use with ephemeral keys.

### SIKE Key Encapsulation

The SIKE encapsulation and decapsulation process is different for either of the parties and starts on `BOB`'s side:

```java
SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
KeyGenerator keyGenerator = new KeyGenerator(sikeParam);
KeyPair keyPairB = keyGenerator.generateKeyPair(Party.BOB);
```

Bob's public key `keyPairB` is transported to `ALICE` who uses the public key for the encapsulation phase of the KEM:

```java
EncapsulationResult encapsulationResult = sike.encapsulate(keyPairB.getPublic());
EncryptedMessage encryptedMessage = encapsulationResult.getEncryptedMessage();
byte[] secretA = encapsulationResult.getSecret();
```

The encrypted message `encryptedMessage` is transported to `BOB` who uses the public key and cipher text included
in the message for the decapsulation phase of KEM:

```java
byte[] secretB = sike.decapsulate(keyPair.getPrivate(), keyPair.getPublic(), encryptedMessage);
```

Both secrets `secretA` and `secretB` are equal in case the key encapsulation and decapsulation succeeded. The shared 
secret sizes are listed in the table presented in the [Initialization chapter](./Readme.md#Initialization).

Note that SIKE provides higher security than SIDH, it is an ind-CCA2 scheme and can be used with long term keys.