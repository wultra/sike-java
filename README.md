# SIKE for Java

[![Build Status](https://travis-ci.org/wultra/sike-java.svg?branch=develop)](https://travis-ci.org/wultra/sike-java)
[![GitHub issues](https://img.shields.io/github/issues/wultra/sike-java.svg)](https://github.com/wultra/sike-java/issues)
[![Twitter](https://img.shields.io/badge/twitter-@wultra-blue.svg?style=flat)](http://twitter.com/wultra)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

SIKE for Java is a software library that implements experimental supersingular isogeny cryptographic schemes that aim to provide protection against attackers running a large-scale quantum computer. The library is a result of a security research cooperation between [Wultra](https://wultra.com) and [Raiffeisen Bank International](http://www.rbinternational.com/) Competence Centre for Cryptology and Biometrics.

We advise the readers who are new to SIDH or SIKE to check the official resources, which provide many educational materials.

- The ["Supersingular isogeny key exchange for beginners"](https://eprint.iacr.org/2019/1321.pdf) article explains the main concepts nicely.
- Official SIKE documentation: https://sike.org
- SIKE specification from round 3 NIST submission: https://sike.org/files/SIDH-spec.pdf
- The ["Mathematics of Isogeny Based Cryptography"](https://arxiv.org/pdf/1711.04062.pdf) paper provides an introduction to the mathematics used by these algorithms.

## Features

The port of SIKE to Java provides the following functionality:

- Key generation
- SIDH key exchange
- SIKE public key encryption (PKE)
- SIKE key encapsulation mechanism (KEM)

Following SIKE parameter sets are supported:

- SIKEp434
- SIKEp503
- SIKEp610
- SIKEp751

The project provides implementation ports for both reference and optimized implementations, and it is possible to switch the implementation type. The port currently does not support compressed keys. The field arithmetics is based on Java BigInteger in the reference implementation. The optimized implementation uses an unsigned long array representation of field elements, and the field arithmetics does not use any native code.

The private and public keys can be exported into:

- an octet representation as defined in the SIKE specification
- a byte array representation useful for a more optimal encoding

The private and public keys can be imported from either of these serialization formats.

The port includes KAT test vectors for all supported SIKE parameter sets.

Note that this port's aim was not to create a 100% identical port with the C code because the original syntax is not object-oriented. There are small differences between the C and Java implementations. However, given the passing KAT test vectors, the
implementations should be 100% compatible.

## Getting Started

If you prefer watching a video over reading a manual, you can watch the [Getting Started Video](https://www.youtube.com/watch?v=0IK4XCY4qm8) which provides an introduction to using this library. 

## Usage

SIKE for Java provides an easy to use interface for generating keys and computing shared secrets.

### Installation

#### Install Using Maven

The artifacts are currently not published in any public repository given the experimental stage of the implementation. Clone the project and install the artifact in the local Maven repository to use the library by running the following commands:

```sh
$ git clone https://github.com/wultra/sike-java.git
$ cd sike-java
$ git checkout tags/0.1.0 -b tags/0.1.0
$ mvn clean install
```

After that, add the following dependency in your project `pom.xml` file:

```xml
<dependency>
    <groupId>com.wultra.security</groupId>
    <artifactId>sike-java</artifactId>
    <version>0.1.0</version>
</dependency>
``` 

#### Use JAR File

Alternatively, use a pre-compiled `sike-java.jar` artifact from the [releases page](https://github.com/wultra/sike-java/releases).

### Initialization

As the first step, initialize the Bouncy Castle provider:

```java
Security.addProvider(new BouncyCastleProvider());
```

Initialize Bouncy Castle at the application start before using any of the SIKE for Java functionality.

Before generating keys, choose one of the available algorithm parameter sets depending on the desired NIST security level and parameter size (in bytes):

| SIKE Parameter Set | NIST Security Level | Private Key Size | Public Key Size | Shared Secret Size |
| :---------------: | :-----------------: | :--------------: | :-------------: | :----------------: | 
| SIKEp434 | 1 | 374 | 330 | 16 |
| SIKEp503 | 2 | 434 | 378 | 24 |
| SIKEp610 | 3 | 524 | 462 | 24 |
| SIKEp751 | 5 | 644 | 564 | 32 |

Two implementations are available:

 - `REFERENCE` - slow implementation with a focus on readability of code 
 - `OPTIMIZED` - fast implementation with a focus on performance and security

The selected SIKE parameters need to be created using: 

```java 
SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
```

### Generating Keys

Generate key pairs using the `KeyGenerator` class: 
 
```java
KeyGenerator keyGenerator = new KeyGenerator(sikeParam);
```

Before generating a key pair, decide whether the party is `ALICE` or `BOB`. 

For SIKE, `ALICE` is the server, and `BOB` is the client that initiates the communication.

To generate a key pair for `ALICE`, use:

```java
KeyPair keyPairA = keyGenerator.generateKeyPair(Party.ALICE);
``` 

To generate a key pair for `BOB`, use:

```java
KeyPair keyPairB = keyGenerator.generateKeyPair(Party.BOB);
``` 

Obtain the keys from the key pair using:

```java
PrivateKey priv = keyPair.getPrivate();
PrivateKey pub = keyPair.getPrivate();
```

To export the keys into a byte array, call either of these methods:
- `getEncoded()` - returns the byte array representation of the key
- `toOctetString()` - converts the key to an octet string as defined in SIKE specification, you need to cast the key to `SidhPrivateKey` or `SidhPublicKey` to access this method

Obtain the numeric representation of keys using:

- `priv.getKey()` - returns the `FpElement` representing the private key
- `pub.getPx()` - returns the `Fp2Element` representing the public key element `phi(Px)`
- `pub.getQx()` - returns the `Fp2Element` representing the public key element `phi(Qx)`
- `pub.getRx()` - returns the `Fp2Element` representing the public key element `phi(Rx)`

Obtain the BigInteger representations of the keys using:

- `priv.getM()` - returns the `BigInteger` representing the private key
- `pub.getPx().getX0().getX()` - returns the `BigInteger` representing the real part of public key `x` coordinate `phi(Px)`
- `pub.getPx().getX1().getX()` - returns the `BigInteger` representing the imaginary part of public key `x` coordinate `phi(Px)`

Obtaining BigInteger representations of `x` coordinates of `phi(Qx)` and `phi(Rx)` is analogous to `phi(Px)`.

Import private keys from their byte array representation:

```java
SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
byte[] secret = secretBytes;
PrivateKey priv = new SidhPrivateKey(sikeParam, Party.ALICE, secret);
```

It is also possible to import private keys from their octet string representation:

```java
SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
String secret = secretOctets;
PrivateKey priv = new SidhPrivateKey(sikeParam, Party.ALICE, secret);
```

Finally, it is also possible to import private keys from their `BigInteger` representation:

```java
SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
BigInteger secret = new BigInteger(secretNumber);
PrivateKey priv = new SidhPrivateKey(sikeParam, Party.ALICE, secret);
```

Once having a private key, derive the public key using:

```java
PublicKey pub = keyGenerator.derivePublicKey(Party.ALICE);
```

Public keys can also be imported from various serialization formats using the `SidhPublicKey` class constructors.

### SIDH Key Agreement

SIDH is an underlying algorithm used in SIKE. Unlike SIKE, SIDH alone provides insufficient security (it is an [IND-CPA](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability) scheme) and should only be used with ephemeral keys on both sides of the key exchange. As a result, we recommend not using SIDH for anything else but experiments. This documentation mentions SIDH mostly for the purpose of completeness.

<details>
<summary><b>⚠️ Continue Reading About SIDH</b></summary>
    
After initializing the keys for both parties, it is easy to compute the shared secret using SIDH. The process is the same for both parties. Similarly to DH or ECDH, SIDH uses the opposite public and private keys:

```java
Sidh sidh = new Sidh(sikeParam);
Fp2Element secretA = sidh.generateSharedSecret(Party.ALICE, keyPairA.getPrivate(), keyPairB.getPublic());
Fp2Element secretB = sidh.generateSharedSecret(Party.BOB, keyPairB.getPrivate(), keyPairA.getPublic());
```

Obtain the byte array representing secret j-invariants of both sides using:

```java
byte[] encoded = secret.getEncoded();
```

Both secrets `secretA` and `secretB` are equal in case the key agreement succeeded. The shared secret sizes match the `Fp2Element` sizes in the chosen SIKE parameter set, which is 1/3 of the public key size. Using a hashing function on the shared secret value is advised to obtain shorter shared secret sizes as well as eliminate any risks related to using the numeric representation of the j-invariant directly.
</details>

### SIKE Key Encapsulation

The SIKE encapsulation and decapsulation process is different for either of the parties and starts on `BOB`'s side:

```java
SikeParam sikeParam = new SikeParamP434(ImplementationType.OPTIMIZED);
KeyGenerator keyGenerator = new KeyGenerator(sikeParam);
KeyPair keyPairB = keyGenerator.generateKeyPair(Party.BOB);
```

`BOB` transports his public key `keyPairB` to `ALICE`, who uses the public key for the encapsulation phase of the KEM:

```java
Sike sike = new Sike(sikeParam);
EncapsulationResult encapsulationResult = sike.encapsulate(keyPairB.getPublic());
```

At this point, `ALICE` can calculate the shared secret and the encrypted message:

```java
byte[] secretA = encapsulationResult.getSecret();
EncryptedMessage encryptedMessage = encapsulationResult.getEncryptedMessage();
```

The encrypted message `encryptedMessage` is transported back to `BOB` who uses the public key and cipher text included in the message for the decapsulation phase of KEM:

```java
byte[] secretB = sike.decapsulate(keyPairB.getPrivate(), keyPairB.getPublic(), encryptedMessage);
```

Both secrets `secretA` and `secretB` are equal in case the key encapsulation and decapsulation succeeded. The shared secret sizes are listed in the table presented in the [Initialization chapter](./README.md#Initialization).  Using a hashing function on the shared secret value is advised to obtain shorter shared secret sizes as well as eliminate any risks related to using the numeric representation of the j-invariant directly.

Note that SIKE provides higher security than SIDH. It is an [IND-CCA2](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability) scheme and can be used with long term keys.

## License

SIKE for Java is currently licensed using [GNU AGPLv3](https://github.com/wultra/sike-java/blob/develop/LICENSE) license. We may change the license in the future to a less restrictive one. Please consult us at [hello@wultra.com](mailto:hello@wultra.com) for the software use.

Oracle and Java are registered trademarks of Oracle and/or its affiliates. Other names may be trademarks of their respective owners.
