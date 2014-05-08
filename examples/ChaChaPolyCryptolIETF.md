# ChaCha20 and Poly1305 for IETF protocols 
 * Y. Nir (Check Point)
 * A. Langley (Google Inc)
 * D. McNamee (Galois, Inc)

May 8, 2014

## Abstract

This document defines the ChaCha20 stream cipher, as well as the use
of the Poly1305 authenticator, both as stand-alone algorithms, and as
a "combined mode", or Authenticated Encryption with Additional Data
(AEAD) algorithm.

This document does not introduce any new crypto, but is meant to
serve as a stable reference and an implementation guide.

This document is a translation of the IETF draft document
draft-nir-cfrg-chacha20-poly1305-02 into "literate Cryptol".
This document can be loaded and executed by a Cryptol interpreter.
There is an open source implementation of Cryptol available at http://cryptol.net

## Copyright Notice

Copyright (c) 2014 IETF Trust and the persons identified as the
document authors.  All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal
Provisions Relating to IETF Documents
(http://trustee.ietf.org/license-info) in effect on the date of
publication of this document.  Please review these documents
carefully, as they describe your rights and restrictions with respect
to this document.

# Introduction

The Advanced Encryption Standard (AES - [FIPS-197]) has become the
gold standard in encryption.  Its efficient design, wide
implementation, and hardware support allow for high performance in
many areas.  On most modern platforms, AES is anywhere from 4x to 10x
as fast as the previous most-used cipher, 3-key Data Encryption
Standard (3DES - [FIPS-46]), which makes it not only the best choice,
but the only choice.

The problem is that if future advances in cryptanalysis reveal a
weakness in AES, users will be in an unenviable position.  With the
only other widely supported cipher being the much slower 3DES, it is
not feasible to re-configure implementations to use 3DES.
[standby-cipher] describes this issue and the need for a standby
cipher in greater detail.

This document defines such a standby cipher.  We use ChaCha20
([chacha]) with or without the Poly1305 ([poly1305]) authenticator.
This algorithm is not just fast and secure.  It is fast even if
software-only C-language implementations, allowing for much quicker
deployment when compared with algorithms such as AES that are
significantly accelerated by hardware implementations.

These document does not introduce this new algorithm.  It has
been defined in scientific papers by D. J. Bernstein, which are
referenced by this document.  The purpose of this document is to
serve as a stable reference for IETF documents making use of these
algorithms.

## Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC2119].

The description of the ChaCha algorithm will at various time refer to
the ChaCha state as a "vector" or as a "matrix".  This follows the
use of these terms in DJB's paper.  The matrix notation is more
visually convenient, and gives a better notion as to why some rounds
are called "column rounds" while others are called "diagonal rounds".
Here's a diagram of how matrices relate to vectors (using the C
language convention of zero being the index origin).

```example
    0 , 1 ,  2 ,  3,
    4 , 5 ,  6 ,  7,
    8 , 9 ,  10,  11,
    12, 13,  14,  15
```

The elements in this vector or matrix are 32-bit unsigned integers.

```cryptol
module ChaCha20 where

type ChaChaState = [16][32]
```

The algorithm name is "ChaCha".  "ChaCha20" is a specific instance
where 20 "rounds" (or 80 quarter rounds - see Section 2.1) are used.
Other variations are defined, with 8 or 12 rounds, but in this
document we only describe the 20-round ChaCha, so the names "ChaCha"
and "ChaCha20" will be used interchangeably.

# The Algorithms

The subsections below describe the algorithms used.

## The ChaCha Quarter Round

The basic operation of the ChaCha algorithm is the quarter round.  It
operates on four 32-bit unsigned integers, denoted a, b, c, and d.
The operation is as follows:

```cryptol
ChaChaQuarterround : [4][32] -> [4][32]
ChaChaQuarterround [a, b, c, d] = [a'', b'', c'', d''] where
    a' = a + b
    d' = (d ^ a') <<< 16
    c' = c + d'
    b' = (b ^ c') <<< 12
    a'' = a' + b'
    d'' = (d' ^ a'') <<< 8
    c'' = c' + d''
    b'' = (b' ^ c'') <<< 7
```

Where "+" denotes integer addition without carry, "^" denotes a
bitwise XOR, and "<<< n" denotes an n-bit left rotation (towards the
high bits).

For example, let's see the add, XOR and roll operations from the
first two lines with sample numbers:

 *  b = 0x01020304
 *  a = 0x11111111
 *  d = 0x01234567
 *  a = a + b = 0x11111111 + 0x01020304 = 0x12131415
 *  d = d ^ a = 0x01234567 ^ 0x12131415 = 0x13305172
 *  d = d<<<16 = 0x51721330

### Test Vector for the ChaCha Quarter Round

For a test vector, we will use the same numbers as in the example,
adding something random for c.


After running a Quarter Round on these 4 numbers, we get these:

```cryptol
property ChaChaQuarterround_passes_test =
    ChaChaQuarterround [ 0x11111111 // a
                       , 0x01020304 // b
                       , 0x9b8d6f43 // c
                       , 0x01234567 // d
                       ]
    ==
                       [ 0xea2a92f4
                       , 0xcb1cf8ce
                       , 0x4581472e
                       , 0x5881c4bb
                       ]
```

## A Quarter Round on the ChaCha State

The ChaCha state does not have 4 integer numbers, but 16.  So the
quarter round operation works on only 4 of them - hence the name.
Each quarter round operates on 4 pre-determined numbers in the ChaCha
state.  We will denote by QUATERROUND(x,y,z,w) a quarter-round
operation on the numbers at indexes x, y, z, and w of the ChaCha
state when viewed as a vector.  For example, if we apply
QUARTERROUND(1,5,9,13) to a state, this means running the quarter
round operation on the elements marked with an asterisk, while
leaving the others alone:

```example
0   *a   2   3
4   *b   6   7
8   *c  10  11
12  *d  14  15
```

Note that this run of quarter round is part of what is called a
"column round".

## The ChaCha20 block Function

The ChaCha block function transforms a ChaCha state by running
multiple quarter rounds.

The inputs to ChaCha20 are:

 * A 256-bit key, treated as a concatenation of 8 32-bit little-endian integers.
 * A 96-bit nonce, treated as a concatenation of 3 32-bit little-endian integers.
 * A 32-bit block count parameter, treated as a 32-bit little-endian integer.

The output is 64 random-looking bytes.

The ChaCha algorithm described here uses a 256-bit key.  The original
algorithm also specified 128-bit keys and 8- and 12-round variants,
but these are out of scope for this document.  In this section we
describe the ChaCha block function.

```cryptol
type ChaChaKey = [256]
```

Note also that the original ChaCha had a 64-bit nonce and 64-bit
block count.  We have modified this here to be more consistent with
recommendations in section 3.2 of [RFC5116].  This limits the use of
a single (key,nonce) combination to 2^32 blocks, or 256 GB, but that
is enough for most uses.  In cases where a single key is used by
multiple senders, it is important to make sure that they don't use
the same nonces.  This can be assured by partitioning the nonce space
so that the first 32 bits are unique per sender, while the other 64
bits come from a counter.

The ChaCha20 as follows:

 * The first 4 words (0-3) are constants: 0x61707865, 0x3320646e,
   0x79622d32, 0x6b206574.

```cryptol
FirstRow = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
property FirstRow_correct = groupBy`{8}(join [ littleendian (split w)
                                             | w <- FirstRow ])
                            == "expand 32-byte k"
```

 * The next 8 words (4-11) are taken from the 256-bit key by
   reading the bytes in little-endian order, in 4-byte chunks.

```cryptol
KeyToRows : ChaChaKey -> [8][32]
KeyToRows key = [littleendian (split words) | words <- (split key)]
```

 * Word 12 is a block counter.  Since each block is 64-byte,
   a 32-bit word is enough for 256 Gigabytes of data.
 * Words 13-15 are a nonce, which should not be repeated for the same
   key.  The 13th word is the first 32 bits of the input nonce taken
   as a little-endian integer, while the 15th word is the last 32
   bits.

```cryptol
/*
    Initial state structure:

    cccccccc  cccccccc  cccccccc  cccccccc
    kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
    kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
    bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

    c=constant k=key b=blockcount n=nonce
*/

NonceToRow : [96] -> [32] -> [4][32]
NonceToRow n i = [i] # [ littleendian (split words) | words <- groupBy`{32} n ]
```

```cryptol
BuildState : ChaChaKey -> [96] -> [32] -> [16][32]
BuildState key nonce i = split (join (FirstRow # KeyToRows key # NonceToRow nonce i))
```

ChaCha20 runs 20 rounds, alternating between "column" and "diagonal"
rounds.  Each round is 4 quarter-rounds, and they are run as follows.
Rounds 1-4 are part of the "column" round, while 5-8 are part of the
"diagonal" round:

```cryptol
columns = [ 0, 4, 8,  12,   // round 1 - column round
            1, 5, 9,  13,   // round 2
            2, 6, 10, 14,   // round 3
            3, 7, 11, 15 ]  // round 4
diags  = [ 0, 5, 10, 15,    // round 5 - diagonal round
           1, 6, 11, 12,    // round 6
           2, 7, 8,  13,    // round 7
           3, 4, 9,  14 ]   // round 8
```

The Cryptol pattern of using the `@@` operator on permutations of the indices of
the matrix creates a new matrix that consists of rows that correspond to the
quarter-round calls. To restore the element-indices to their original ordering,
after each application we permute by the inverse permutation. Since the column
round is just a square matrix transposition, it inverts itself, but the
diagonal round needs to have an inverse permutation calculated, which we do
here:

```cryptol
inversePermutation (perms:[a+1]b) = [ indexOf i perms | i <- [ 0 .. a ] ]
invDiags = inversePermutation diags
invCols  = inversePermutation columns // which happens to be the same as columns

ChaChaTwoRounds (xs:ChaChaState) = xs'' where
    xs'  =  join [ChaChaQuarterround x | x <- groupBy`{4}(xs@@columns) ] @@ invCols
    xs'' = (join [ChaChaQuarterround x | x <- groupBy`{4}(xs'@@diags ) ]) @@ invDiags

ChaCha : ChaChaState -> [8] -> ChaChaState
ChaCha s n = chain@n where
    chain = [s] # [ ChaChaTwoRounds ci | ci <- chain | i <- [0 .. 9] ]
```

At the end of 20 rounds, the original input words are added to the
output words, and the result is serialized by sequencing the words
one-by-one in little-endian order.

```cryptol
ChaCha20Block : ChaChaKey -> [96] -> [32] -> ChaChaState
ChaCha20Block key nonce i = (ChaCha initialState 10) + initialState where
    initialState = BuildState key nonce i
```

### Test Vector for the ChaCha20 Block Function

For a test vector, we will use the following inputs to the ChaCha20
block function:

```cryptol
TestKey : ChaChaKey
TestKey = join
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
     0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
     0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]
```

The key is a sequence of octets with no particular structure before we copy it
into the ChaCha state.

```cryptol
TestNonce : [96]
TestNonce = 0x000000090000004a00000000
```

After setting up the ChaCha state, it looks like this:

ChaCha State with the key set up.

```cryptol
TestState = BuildState TestKey TestNonce 1

property BuildState_correct = TestState == [
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    0x00000001, 0x09000000, 0x4a000000, 0x00000000 ]
```

After running 20 rounds (10 column rounds interleaved with 10
diagonal rounds), the ChaCha state looks like this:

ChaCha State after 20 rounds

```cryptol
ChaCha20_state1 = [
    0x837778ab, 0xe238d763,  0xa67ae21e,  0x5950bb2f,
    0xc4f2d0c7, 0xfc62bb2f,  0x8fa018fc,  0x3f5ec7b7,
    0x335271c2, 0xf29489f3,  0xeabda8fc,  0x82e46ebd,
    0xd19c12b4, 0xb04e16de,  0x9e83d0cb,  0x4e3c50a2
    ]

property ChaChaStateAfter20_correct = ChaCha TestState 10 == ChaCha20_state1
```

Finally we add the original state to the result (simple vector or
matrix addition), giving this:

ChaCha State at the end of the ChaCha20 operation

```cryptol
ChaCha20_block_1 = [
    0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
    0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
    0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
    0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    ]

property ChaCha20_test1 = ChaCha20Block TestKey TestNonce 1 == ChaCha20_block_1
```

## The ChaCha20 encryption algorithm

ChaCha20 is a stream cipher designed by D. J. Bernstein.  It is a
refinement of the Salsa20 algorithm, and uses a 256-bit key.

ChaCha20 successively calls the ChaCha20 block function, with the
same key and nonce, and with successively increasing block counter
parameters.  The resulting state is then serialized by writing the
numbers in little-endian order.  Concatenating the results from the
successive blocks forms a key stream, which is then XOR-ed with the
plaintext.  There is no requirement for the plaintext to be an
integral multiple of 512-bits.  If there is extra keystream from the
last block, it is discarded.  Specific protocols MAY require that the
plaintext and ciphertext have certain length.  Such protocols need to
specify how the plaintext is padded, and how much padding it
receives.

The inputs to ChaCha20 are:

 *   A 256-bit key
 *   A 32-bit initial counter.  This can be set to any number, but will
     usually be zero or one.  It makes sense to use 1 if we use the
     zero block for something else, such as generating a one-time
     authenticator key as part of an AEAD algorithm.
 *   A 96-bit nonce.  In some protocols, this is known as the
     Initialization Vector.
 *   an arbitrary-length plaintext

The output is an encrypted message of the same length.

```cryptol
ChaCha20ExpandKey : ChaChaKey -> [96] -> [32] -> [inf]ChaChaState
ChaCha20ExpandKey k n i = [ ToLittleEndian (ChaCha20Block k n j)
                          | j <- ([i ...]:[_][32])
                          ]

ChaCha20EncryptBytes msg k n i= [ m ^ kb | m <- msg | kb <- keystream ] where
    keystream = groupBy`{8}(join (join (ChaCha20ExpandKey k n i)))
```

### Example and Test Vector for the ChaCha20 Cipher

For a test vector, we will use the following inputs to the ChaCha20
block function:

```cryptol
Sunscreen_Key = join
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
     0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
     0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]
Sunscreen_Nonce = 0x000000000000004a00000000
Sunscreen_Initial_Counter = 1
```

We use the following for the plaintext.  It was chosen to be long
enough to require more than one block, but not so long that it would
make this example cumbersome (so, less than 3 blocks):

Plaintext Sunscreen:

```cryptol
Plaintext_Sunscreen = "Ladies and Gentlemen of the class of '99: " #
                      "If I could offer you only one tip for the " #
                      "future, sunscreen would be it."
```

The following figure shows 4 ChaCha state matrices:

 1.  First block as it is set up.
 1.  Second block as it is set up.  Note that these blocks are only
        two bits apart - only the counter in position 12 is different.
 1.  Third block is the first block after the ChaCha20 block
        operation.
 1.  Final block is the second block after the ChaCha20 block
        operation was applied.

After that, we show the keystream.

First block setup:

```cryptol
Sunscreen_State1 = [
    0x61707865,  0x3320646e,  0x79622d32,  0x6b206574,
    0x03020100,  0x07060504,  0x0b0a0908,  0x0f0e0d0c,
    0x13121110,  0x17161514,  0x1b1a1918,  0x1f1e1d1c,
    0x00000001,  0x00000000,  0x4a000000,  0x00000000
    ]

property SunscreenBuildState_correct =
    BuildState Sunscreen_Key Sunscreen_Nonce 1 == Sunscreen_State1
```

Second block setup:

```cryptol
Sunscreen_State2 = [
    0x61707865,  0x3320646e,  0x79622d32,  0x6b206574,
    0x03020100,  0x07060504,  0x0b0a0908,  0x0f0e0d0c,
    0x13121110,  0x17161514,  0x1b1a1918,  0x1f1e1d1c,
    0x00000002,  0x00000000,  0x4a000000,  0x00000000
    ]

property SunscreenBuildState2_correct =
    BuildState Sunscreen_Key Sunscreen_Nonce 2 == Sunscreen_State2
```

First block after block operation:

```cryptol
SunscreenAfterBlock1 = [
    0xf3514f22, 0xe1d91b40, 0x6f27de2f, 0xed1d63b8,
    0x821f138c, 0xe2062c3d, 0xecca4f7e, 0x78cff39e,
    0xa30a3b8a, 0x920a6072, 0xcd7479b5, 0x34932bed,
    0x40ba4c79, 0xcd343ec6, 0x4c2c21ea, 0xb7417df0
    ]

property SunscreenBlock1_correct =
    ChaCha20Block Sunscreen_Key Sunscreen_Nonce 1 == SunscreenAfterBlock1
```

Second block after block operation:

```cryptol
SunscreenAfterBlock2 = [
    0x9f74a669, 0x410f633f, 0x28feca22, 0x7ec44dec,
    0x6d34d426, 0x738cb970, 0x3ac5e9f3, 0x45590cc4,
    0xda6e8b39, 0x892c831a, 0xcdea67c1, 0x2b7e1d90,
    0x037463f3, 0xa11a2073, 0xe8bcfb88, 0xedc49139
    ]

property SunscreenBlock2_correct =
    ChaCha20Block Sunscreen_Key Sunscreen_Nonce 2 == SunscreenAfterBlock2
```

Keystream:

```cryptol
SunscreenKeystream =
    [0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1, 0x2f, 0xde, 0x27,
     0x6f, 0xb8, 0x63, 0x1d, 0xed, 0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c,
     0x06, 0xe2, 0x7e, 0x4f, 0xca, 0xec, 0x9e, 0xf3, 0xcf, 0x78, 0x8a,
     0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92, 0xb5, 0x79, 0x74, 0xcd,
     0xed, 0x2b, 0x93, 0x34, 0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34,
     0xcd, 0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7, 0x69, 0xa6,
     0x74, 0x9f, 0x3f, 0x63, 0x0f, 0x41, 0x22, 0xca, 0xfe, 0x28, 0xec,
     0x4d, 0xc4, 0x7e, 0x26, 0xd4, 0x34, 0x6d, 0x70, 0xb9, 0x8c, 0x73,
     0xf3, 0xe9, 0xc5, 0x3a, 0xc4, 0x0c, 0x59, 0x45, 0x39, 0x8b, 0x6e,
     0xda, 0x1a, 0x83, 0x2c, 0x89, 0xc1, 0x67, 0xea, 0xcd, 0x90, 0x1d,
     0x7e, 0x2b, 0xf3, 0x63]

property SunscreenKeystream_correct (skref:[skwidth][8]) =
    take`{skwidth}
        (groupBy`{8} (join (join(ChaCha20ExpandKey
                                    Sunscreen_Key Sunscreen_Nonce 1)))) == skref
```

We XOR the Keystream with the plaintext, yielding the Ciphertext:

```cryptol
Ciphertext_Sunscreen =
    [0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07,
     0x28, 0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43,
     0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9,
     0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab,
     0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52,
     0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca,
     0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a,
     0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
     0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b,
     0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78,
     0x5e, 0x42, 0x87, 0x4d]

property ChaCha_encrypt_sunscreen_correct =
    ChaCha20EncryptBytes Plaintext_Sunscreen Sunscreen_Key Sunscreen_Nonce 1
    == Ciphertext_Sunscreen
```

Finally, decrypt is the same as encrypt:

```cryptol
ChaCha20DecryptBytes = ChaCha20EncryptBytes

property Sunscreen_decrypt_correct =
    ChaCha20DecryptBytes Ciphertext_Sunscreen Sunscreen_Key Sunscreen_Nonce 1
    == Plaintext_Sunscreen
```

# The Poly1305 algorithm

Poly1305 is a one-time authenticator designed by D. J. Bernstein.
Poly1305 takes a 32-byte one-time key and a message and produces a
16-byte tag.

The original article ([poly1305]) is entitled "The Poly1305-AES
message-authentication code", and the MAC function there requires a
128-bit AES key, a 128-bit "additional key", and a 128-bit (non-
secret) nonce.  AES is used there for encrypting the nonce, so as to
get a unique (and secret) 128-bit string, but as the paper states,
"There is nothing special about AES here.  One can replace AES with
an arbitrary keyed function from an arbitrary set of nonces to 16-
byte strings.".

Regardless of how the key is generated, the key is partitioned into
two parts, called "r" and "s".  The pair ``(r,s)`` should be unique, and
MUST be unpredictable for each invocation (that is why it was
originally obtained by encrypting a nonce), while "r" MAY be
constant, but needs to be modified as follows before being used: ("r"
is treated as a 16-octet little-endian number):

 *  r[3], r[7], r[11], and r[15] are required to have their top four
    bits clear (be smaller than 16)

```cryptol
Om = 15 // odd masks - for 3, 7, 11 & 15
```
 *  r[4], r[8], and r[12] are required to have their bottom two bits
    clear (be divisible by 4)

```cryptol
Em = 252 // even masks - for 4, 8 & 12
nm = 255 // no mask
```

```cryptol
PolyMasks : [16][8]            // mask indices
PolyMasks = [ nm, nm, nm, Om,  // 0-3
              Em, nm, nm, Om,  // 4-7
              Em, nm, nm, Om,  // 8-11
              Em, nm, nm, Om ] // 12-15

Poly1305_clamp : [16][8] -> [16][8]
Poly1305_clamp r = [ re && mask | re <- r | mask <- PolyMasks ]
```

The "s" should be unpredictable, but it is perfectly acceptable to
generate both "r" and "s" uniquely each time.  Because each of them
is 128-bit, pseudo-randomly generating them (see Section 2.6) is also
acceptable.

The inputs to Poly1305 are:

 *  A 256-bit one-time key
 *  An arbitrary length message (comprised of `floorBlocks` 16-byte blocks,
    and `rem` bytes left over)

The output is a 128-bit tag.

```cryptol
Poly1305 : {m, floorBlocks, rem} (fin m, floorBlocks == m/16, rem == m - floorBlocks*16) 
           => [256] -> [m][8] -> [16][8]
```

Set the constant prime "P" be 2^130-5.

```cryptol
P:[136]
P = (2^^130)-5
```

```cryptol
Poly1305 key msg = result where
    [ru, su] = split key
```

 * First, the "r" value should be clamped.

```cryptol
    r : [136] // internal arithmetic on (128+8)-bit numbers
    r = littleendian ((Poly1305_clamp (split ru)) # [0x00])
    s = littleendian ((split su) # [0x00])
```

 * Next, divide the message into 16-byte blocks. The last block might be shorter.
 * Read each block as a little-endian number.
 * Prepend a 0x01 byte beyond the number of octets. For a 16-byte block this
   is equivalent to adding 2^128 to the number. XXX - this is because the number is in big-endian form?

```cryptol
    // pad all the blocks uniformly (we'll handle the final block later)
    paddedBlocks = [ 0x01 # (littleendian block)
                   | block <- groupBy`{16}(msg # (zero:[inf][8])) ]
```
 * If the block is not 17 bytes long (the last block), then left-pad it with
   zeros.  This is meaningless if you're treating it them as numbers.

```cryptol
    lastBlock : [136]
    lastBlock = zero # 0x01 # (littleendian (drop`{16*floorBlocks} msg))
```

 *  Initialize the accumulator to zero, then for each block
    *  Add this number to the accumulator.
    *  Multiply by "r"
    *  Set the accumulator to the result modulo p.  To summarize: Acc =
       ((Acc+block)*r) % p.

```cryptol
    accum:[_][136]
    accum = [zero:[136]] # [ computeElt a b r P | a <- accum | b <- paddedBlocks ]
```

 * If the block division leaves no remainder, the last value of the accumulator is good
   otherwise compute the special-case padded block, and compute the final value of the accumulator

```cryptol
    lastAccum : [136]
    lastAccum = if `rem == 0
                   then accum@`floorBlocks
                   else computeElt (accum@`floorBlocks) lastBlock r P
```

 * Finally, the value of the secret key "s" is added to the accumulator,
   and the 128 least significant bits are serialized in little-endian
   order to form the tag.

```cryptol
    result = reverse (groupBy`{8} (drop`{8}(lastAccum + s)))

// Compute ((a + b) * r ) % P being pedantic about bit-widths
computeElt : [136] -> [136] -> [136] -> [136] -> [136]
computeElt a b r p = (drop`{137}bigResult) where
    bigResult : [273]
    aPlusB : [137]
    timesR : [273]
    aPlusB = (0b0#a) + (0b0#b)                        // make room for carry
    timesR = ((zero:[136])#aPlusB) * ((zero:[137])#r) // [a]*[b]=[a+b]
    bigResult = timesR % (zero#P) // bigP

```

A simple test vector:

```cryptol
Poly1305TestKey = join
    [0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52,
     0xfe, 0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d,
     0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b]

Poly1305Message = "Cryptographic Forum Research Group"

property Poly1305_passes_test = Poly1305 Poly1305TestKey Poly1305Message ==
    [ 0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
      0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9 ]
```

## Generating the Poly1305 key using ChaCha20

As said in the "Poly 1305 Algorithm" section, it is acceptable to generate
the one-time Poly1305 pseudo-randomly.  This section proposes such a method.

To generate such a key pair (r,s), we will use the ChaCha20 block function
described in the "ChaCha20 block function" section.  This assumes that we have
a 256- bit session key for the MAC function, such as SK_ai and SK_ar in IKEv2,
the integrity key in ESP and AH, or the client_write_MAC_key and
server_write_MAC_key in TLS.  Any document that specifies the use of Poly1305
as a MAC algorithm for some protocol must specify that 256 bits are allocated
for the integrity key.

The method is to call the block function with the following
parameters:

 *  The 256-bit session integrity key is used as the ChaCha20 key.
 *  The block counter is set to zero.
 *  The protocol will specify a 96-bit or 64-bit nonce.  This MUST be
    unique per invocation with the same key, so it MUST NOT be
    randomly generated.  A counter is a good way to implement this,
    but other methods, such as an LFSR are also acceptable.  ChaCha20
    as specified here requires a 96-bit nonce.  So if the provided
    nonce is only 64-bit, then the first 32 bits of the nonce will be
    set to a constant number.  This will usually be zero, but for
    protocols with multiple sender, it may be different for each
    sender, but should be the same for all invocations of the function
    with the same key by a particular sender.

After running the block function, we have a 512-bit state.  We take
the first 256 bits or the serialized state, and use those as the one-
time Poly1305 key: The first 128 bits are clamped, and form "r",
while the next 128 bits become "s".  The other 256 bits are
discarded.

Note that while many protocols have provisions for a nonce for
encryption algorithms (often called Initialization Vectors, or IVs),
they usually don't have such a provision for the MAC function.  In
that case the per-invocation nonce will have to come from somewhere
else, such as a message counter.

### Poly1305 Key Generation Test Vector

   For this example, we'll set:

```cryptol
PolyKeyTest = join
    [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
     0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
     0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f]

PolyNonceTest = join [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
                       0x03, 0x04, 0x05, 0x06, 0x07]
```

The ChaCha state set up with key, nonce, and block counter zero:
```verbatim
     61707865  3320646e  79622d32  6b206574
     83828180  87868584  8b8a8988  8f8e8d8c
     93929190  97969594  9b9a9998  9f9e9d9c
     00000000  00000000  03020100  07060504
```

The ChaCha state after 20 rounds:
```verbatim
     8ba0d58a  cc815f90  27405081  7194b24a
     37b633a8  a50dfde3  e2b8db08  46a6d1fd
     7da03782  9183a233  148ad271  b46773d1
     3cc1875a  8607def1  ca5c3086  7085eb87
```

And that output is also the 32-byte one-time key used for Poly1305.

```cryptol
PolyOutput = join
    [0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40,
     0x27, 0x4a, 0xb2, 0x94, 0x71, 0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd,
     0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46]

GeneratePolyKeyUsingChaCha k n i = join [littleendian (groupBy`{8}b) 
                                        | b <- take `{8}(ChaCha20Block k n i) ]

Poly_passes_test = GeneratePolyKeyUsingChaCha PolyKeyTest PolyNonceTest 0 == PolyOutput
```

## AEAD Construction

Note: Much of the content of this document, including this AEAD
construction is taken from Adam Langley's draft ([agl-draft]) for the
use of these algorithms in TLS.  The AEAD construction described here
is called AEAD_CHACHA20-POLY1305.

AEAD_CHACHA20-POLY1305 is an authenticated encryption with additional
data algorithm.  The inputs to AEAD_CHACHA20-POLY1305 are:

 *  A 256-bit key
 *  A 96-bit nonce - different for each invocation with the same key.
 *  An arbitrary length plaintext
 *  Arbitrary length additional data

```cryptol
AEAD_CHACHA20_POLY1305 : {m, n} (fin m, fin n, 64 >= width m, 64 >= width n)
                       => [256] -> [64] -> [32]
                          -> [m][8] -> [n][8] -> [m+16][8]

AEAD_CHACHA20_POLY1305 k iv c p ad = (ct # tag) where
```

The ChaCha20 and Poly1305 primitives are combined into an AEAD that
takes a 256-bit key and 64-bit IV as follows:

 *  First the 96-bit nonce is constructed by prepending a 32-bit
    constant value to the IV.  This could be set to zero, or could be
    derived from keying material, or could be assigned to a sender.
    It is up to the specific protocol to define the source for that
    32-bit value.

```cryptol
    AeadNonce = c # iv
```
 *  Next, a Poly1305 one-time key is generated from the 256-bit key
    and nonce using the procedure described in Section 2.6.

```cryptol
    PolyKey = GeneratePolyKeyUsingChaCha k AeadNonce 0
```

 *  The ChaCha20 encryption function is called to encrypt the
    plaintext, using the same key and nonce, and with the initial
    counter set to 1.

```cryptol
    ct = ChaCha20EncryptBytes p k AeadNonce 1 // XXX "same key" -> k or PolyKey?
```

 *  The tag is computed by calling the Poly1305 function with
    the Poly1305 key calculated above, and with a message constructed
    as a concatenation of the following:
    *  The additional data
    *  The length of the additional data in octets (as a 64-bit
       little-endian integer).  TBD: bit count rather than octets?
       network order?
    *  The ciphertext
    *  The length of the ciphertext in octets (as a 64-bit little-
       endian integer).  TBD: bit count rather than octets? network
       order?

```cryptol
    ptlen : [8][8]
    ptlen = groupBy`{8}(littleendian (groupBy`{8}(`m:[64]))) 
    adlen : [8][8]
    adlen = groupBy`{8}(littleendian (groupBy`{8}(`n:[64]))) 
    tag   = Poly1305 PolyKey (ad # adlen # ct # ptlen)
```

The output from the AEAD is twofold:

 *  A ciphertext of the same length as the plaintext.
 *  A 128-bit tag, which is the output of the Poly1305 function.

Decryption is pretty much the same thing.

```cryptol
AEAD_CHACHA20_POLY1305_DECRYPT : {m, n} (fin m, fin n,
                                         64 >= width m, 64 >= width n)
                                 => [256] -> [64] -> [32]
                                    -> [m+16][8] -> [n][8]
                                    -> ([m][8], Bit)

AEAD_CHACHA20_POLY1305_DECRYPT k iv c ct ad = (pt, valid) where
    inTag = drop`{m}ct
    inCt = take`{m}ct
    AeadNonce = c # iv
    PolyKey = GeneratePolyKeyUsingChaCha k AeadNonce 0
    pt = ChaCha20DecryptBytes inCt k AeadNonce 1
    ptlen : [8][8]
    ptlen = groupBy`{8}(littleendian (groupBy`{8}(`m:[64])))
    adlen : [8][8]
    adlen = groupBy`{8}(littleendian (groupBy`{8}(`n:[64])))
    tag   = Poly1305 PolyKey (ad # adlen # inCt # ptlen)
    valid = tag == inTag
```

A few notes about this design:

 1.  The amount of encrypted data possible in a single invocation is
     2^32-1 blocks of 64 bytes each, for a total of 247,877,906,880
     bytes, or nearly 256 GB.  This should be enough for traffic
     protocols such as IPsec and TLS, but may be too small for file
     and/or disk encryption.  For such uses, we can return to the
     original design, reduce the nonce to 64 bits, and use the integer
     at position 13 as the top 32 bits of a 64-bit block counter,
     increasing the total message size to over a million petabytes
     (1,180,591,620,717,411,303,360 bytes to be exact).
 1.  Despite the previous item, the ciphertext length field in the
     construction of the buffer on which Poly1305 runs limits the
     ciphertext (and hence, the plaintext) size to 2^64 bytes, or
     sixteen thousand petabytes (18,446,744,073,709,551,616 bytes to
     be exact).

### Example and Test Vector for AEAD_CHACHA20-POLY1305

For a test vector, we will use the following inputs to the
AEAD_CHACHA20-POLY1305 function:

Plaintext:

```cryptol
AeadPt = "Ladies and Gentlemen of the class of '99: " #
         "If I could offer you only one tip for " #
         "the future, sunscreen would be it."

AeadAAD = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
           0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]

AeadKey = join [ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
                 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
                 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94,
                 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
                 0x9c, 0x9d, 0x9e, 0x9f ]

AeadIV = join [ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 ]
```

32-bit fixed-common part:

```cryptol
AeadC = join [0x07, 0x00, 0x00, 0x00]

AeadCT = ChaCha20EncryptBytes AeadPt AeadKey (AeadC # AeadIV) 1

AeadConstruction = (AeadAAD # ADleLen # AeadCT # CTleLen)

AeadPolyKey = GeneratePolyKeyUsingChaCha AeadKey (AeadC # AeadIV) 0

ADleLen : [8][8]
ADleLen = groupBy`{8}(littleendian (groupBy`{8}((width AeadAAD):[64])))

CTleLen : [8][8]
CTleLen = groupBy`{8}(littleendian (groupBy`{8}((width AeadCT):[64])))

AeadTag = Poly1305 AeadPolyKey AeadConstruction
```

Set up for generating poly1305 one-time key (sender id=7):
```verbatim
    61707865  3320646e  79622d32  6b206574
    83828180  87868584  8b8a8988  8f8e8d8c
    93929190  97969594  9b9a9998  9f9e9d9c
    00000000  00000007  43424140  47464544
```

After generating Poly1305 one-time key:
```verbatim
    252bac7b  af47b42d  557ab609  8455e9a4
    73d6e10a  ebd97510  7875932a  ff53d53e
    decc7ea2  b44ddbad  e49c17d1  d8430bc9
    8c94b7bc  8b7d4b4b  3927f67d  1669a432

Poly1305 Key:
7b ac 2b 25 2d b4 47 af 09 b6 7a 55 a4 e9 55 84|{.+%-.G...zU..U.
0a e1 d6 73 10 75 d9 eb 2a 93 75 78 3e d5 53 ff|...s.u..*.ux>.S.
```

```cryptol
Poly1305_r = 0x0455e9a4057ab6080f47b42c052bac7b
Poly1305_s = 0xff53d53e7875932aebd9751073d6e10a
```

```verbatim
Keystream bytes:
9f:7b:e9:5d:01:fd:40:ba:15:e2:8f:fb:36:81:0a:ae:
c1:c0:88:3f:09:01:6e:de:dd:8a:d0:87:55:82:03:a5:
4e:9e:cb:38:ac:8e:5e:2b:b8:da:b2:0f:fa:db:52:e8:
75:04:b2:6e:be:69:6d:4f:60:a4:85:cf:11:b8:1b:59:
fc:b1:c4:5f:42:19:ee:ac:ec:6a:de:c3:4e:66:69:78:
8e:db:41:c4:9c:a3:01:e1:27:e0:ac:ab:3b:44:b9:cf:
5c:86:bb:95:e0:6b:0d:f2:90:1a:b6:45:e4:ab:e6:22:
15:38


Ciphertext:
000  d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2|...4d.`.{...S.~.
016  a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6|...Q)n......6.b.
032  3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b|=..^..g....i..r.
048  1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36|.q.....)....~.;6
064  92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58|...-w......(..X
080  fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc|..$...u.U...H1..
096  3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b|?....Kz..v.e...K
112  61 16                                          |a.


AEAD Construction for input to Poly1305:
000  50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7 0c 00 00 00|PQRS............
016  00 00 00 00 d3 1a 8d 34 64 8e 60 db 7b 86 af bc|.......4d.`.{...
032  53 ef 7e c2 a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7|S.~....Q)n......
048  36 ee 62 d6 3d be a4 5e 8c a9 67 12 82 fa fb 69|6.b.=..^..g....i
064  da 92 72 8b 1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6|..r..q.....)....
080  7e cd 3b 36 92 dd bd 7f 2d 77 8b 8c 98 03 ae e3|~.;6...-w......
096  28 09 1b 58 fa b3 24 e4 fa d6 75 94 55 85 80 8b|(..X..$...u.U...
112  48 31 d7 bc 3f f4 de f0 8e 4b 7a 9d e5 76 d2 65|H1..?....Kz..v.e
128  86 ce c6 4b 61 16 72 00 00 00 00 00 00 00      |...Ka.r.......


Tag:
18:fb:11:a5:03:1a:d1:3a:7e:3b:03:d4:6e:e3:a6:a7
```

```cryptol
property AeadDecrypt_correct = ptGood && isValid where
    (pt,isValid) = AEAD_CHACHA20_POLY1305_DECRYPT AeadKey AeadIV AeadC cypherText AeadAAD
    cypherText = (AEAD_CHACHA20_POLY1305 AeadKey AeadIV AeadC AeadPt AeadAAD)
    ptGood = AeadPt == pt
```

# Implementation Advice

Each block of ChaCha20 involves 16 move operations and one increment
operation for loading the state, 80 each of XOR, addition and Roll
operations for the rounds, 16 more add operations and 16 XOR
operations for protecting the plaintext.  Section 2.3 describes the
ChaCha block function as "adding the original input words".  This
implies that before starting the rounds on the ChaCha state, it is
copied aside only to be added in later.  This would be correct, but
it saves a few operations to instead copy the state and do the work
on the copy.  This way, for the next block you don't need to recreate
the state, but only to increment the block counter.  This saves
approximately 5.5% of the cycles.

It is NOT RECOMMENDED to use a generic big number library such as the
one in OpenSSL for the arithmetic operations in Poly1305.  Such
libraries use dynamic allocation to be able to handle any-sized
integer, but that flexibility comes at the expense of performance as
well as side-channel security.  More efficient implementations that
run in constant time are available, one of them in DJB's own library,
NaCl ([NaCl]).  A constant-time but not optimal approach would be to
naively implement the arithmetic operations for a 288-bit integers,
because even a naive implementation will not exceed 2^288 in the
multiplication of (acc+block) and r.  An efficient constant-time
implementation can be found in the public domain library poly1305-
donna ([poly1305_donna]).


# Security Considerations

The ChaCha20 cipher is designed to provide 256-bit security.

The Poly1305 authenticator is designed to ensure that forged messages
are rejected with a probability of 1-(n/(2^102)) for a 16n-byte
message, even after sending 2^64 legitimate messages, so it is SUF-
CMA in the terminology of [AE].

Proving the security of either of these is beyond the scope of this
document.  Such proofs are available in the referenced academic
papers.

The most important security consideration in implementing this draft
is the uniqueness of the nonce used in ChaCha20.  Counters and LFSRs
are both acceptable ways of generating unique nonces, as is
encrypting a counter using a 64-bit cipher such as DES.  Note that it
is not acceptable to use a truncation of a counter encrypted with a
128-bit or 256-bit cipher, because such a truncation may repeat after
a short time.

The Poly1305 key MUST be unpredictable to an attacker.  Randomly
generating the key would fulfill this requirement, except that
Poly1305 is often used in communications protocols, so the receiver
should know the key.  Pseudo-random number generation such as by
encrypting a counter is acceptable.  Using ChaCha with a secret key
and a nonce is also acceptable.

The algorithms presented here were designed to be easy to implement
in constant time to avoid side-channel vulnerabilities.  The
operations used in ChaCha20 are all additions, XORs, and fixed
rotations.  All of these can and should be implemented in constant
time.  Access to offsets into the ChaCha state and the number of
operations do not depend on any property of the key, eliminating the
chance of information about the key leaking through the timing of
cache misses.

For Poly1305, the operations are addition, multiplication and
modulus, all on >128-bit numbers.  This can be done in constant time,
but a naive implementation (such as using some generic big number
library) will not be constant time.  For example, if the
multiplication is performed as a separate operation from the modulus,
the result will some times be under 2^256 and some times be above
2^256.  Implementers should be careful about timing side-channels for
Poly1305 by using the appropriate implementation of these operations.


# IANA Considerations

There are no IANA considerations for this document.


# Acknowledgements

ChaCha20 and Poly1305 were
invented by Daniel J. Bernstein, and the AEAD construction was
invented by Adam Langley.

Thanks to Robert Ransom and Ilari Liusvaara for their helpful
comments and explanations.

# References

## Normative References

```example
[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
         Requirement Levels", BCP 14, RFC 2119, March 1997.

[chacha]   Bernstein, D., "ChaCha, a variant of Salsa20", Jan 2008.

[poly1305]
         Bernstein, D., "The Poly1305-AES message-authentication
         code", Mar 2005.
```

## Informative References

```example
[AE]       Bellare, M. and C. Namprempre, "Authenticated Encryption:
           Relations among notions and analysis of the generic
           composition paradigm",
           <http://cseweb.ucsd.edu/~mihir/papers/oem.html>.

[FIPS-197]
         National Institute of Standards and Technology, "Advanced
         Encryption Standard (AES)", FIPS PUB 197, November 2001.

[FIPS-46]  National Institute of Standards and Technology, "Data
           Encryption Standard", FIPS PUB 46-2, December 1993,
           <http://www.itl.nist.gov/fipspubs/fip46-2.htm>.

[NaCl]     Bernstein, D., Lange, T., and P. Schwabe, "NaCl:
           Networking and Cryptography library",
           <http://nacl.cace-project.eu/index.html>.

[RFC5116]  McGrew, D., "An Interface and Algorithms for Authenticated
           Encryption", RFC 5116, January 2008.

[agl-draft]
         Langley, A. and W. Chang, "ChaCha20 and Poly1305 based
         Cipher Suites for TLS", draft-agl-tls-chacha20poly1305-04
         (work in progress), November 2013.

[poly1305_donna]
         Floodyberry, A., "Poly1305-donna",
         <https://github.com/floodyberry/poly1305-donna>.

[standby-cipher]
         McGrew, D., Grieco, A., and Y. Sheffer, "Selection of
         Future Cryptographic Standards",
         draft-mcgrew-standby-cipher (work in progress).
```


Authors' Addresses

```verbatim
Yoav Nir
Check Point Software Technologies Ltd.
5 Hasolelim st.
Tel Aviv  6789735
Israel
Email: ynir.ietf@gmail.com

Adam Langley
Google Inc
Email: agl@google.com

Dylan McNamee
Galois Inc
Email: dylan@galois.com
```

# Appendix: Utility functions

```cryptol
indexOf e (xs:[a+1]b) = ixs ! 0 where
    ixs = [ 0 ] #
                 [ if ix == e then j else old
                 | ix <- xs
                 | j <- [ 0 .. a ]
                 | old <- ixs
                 ]

ToLittleEndian : ChaChaState -> ChaChaState
ToLittleEndian s = [littleendian (split words) | words <- s]

// Takes a finite sequence of bytes, and turns them into a word via
// a little-endian interpretation
littleendian : {a}(fin a) => [a][8] -> [a*8]
littleendian b = join(reverse b)

property AllPropertiesPass =
    ChaChaQuarterround_passes_test && FirstRow_correct && BuildState_correct
    && ChaChaStateAfter20_correct && SunscreenBuildState_correct
    && SunscreenBuildState2_correct && SunscreenBlock1_correct
    && SunscreenBlock2_correct && SunscreenKeystream_correct SunscreenKeystream
    && ChaCha_encrypt_sunscreen_correct && ChaCha20_test1
    && Sunscreen_decrypt_correct
    && Poly1305_passes_test
    && AeadDecrypt_correct
```

