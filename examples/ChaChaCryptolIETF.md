% ChaCha20 for IETF protocols
% Y. Nir (Check Point)
  A. Langley (Google Inc)
  D. McNamee (Galois, Inc)
% April 3, 2014

<!--
    Literate Cryptol ChaCha spec
    convert to .pdf (or other output formats) with "pandoc" like so:
    % pandoc --toc -f markdown+lhs ChaChaCryptolIETF.md -o ChaChaCryptolIETF.pdf
    Load into cryptol and test like so:
    cryptol ChaChaCryptolIETF.md
    Cryptol> AllPropertiesPass
    True

```cryptol
module ChaCha20 where
```

--!>

# Abstract

This document defines the ChaCha20 stream cipher.  This document does not
introduce any new crypto, but is meant to serve as a stable reference and an
implementation guide.  This document is the subset of the ChaCha20/Poly1305
document (https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-02)
that describes the ChaCha20 cipher. Dylan McNamee added Literate Cryptol
implementations of the ChaCha20 cipher.

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

```cryptol
identity = [
  0 , 1 ,  2 ,  3,
  4 , 5 ,  6 ,  7,
  8 , 9 ,  10,  11,
  12, 13,  14,  15 ]
```

The elements in this vector or matrix are 32-bit unsigned integers.

```cryptol
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

property AllPropertiesPass =
    ChaChaQuarterround_passes_test && FirstRow_correct && BuildState_correct
    && ChaChaStateAfter20_correct && SunscreenBuildState_correct
    && SunscreenBuildState2_correct && SunscreenBlock1_correct
    && SunscreenBlock2_correct && SunscreenKeystream_correct SunscreenKeystream
    && ChaCha_encrypt_sunscreen_correct && ChaCha20_test1
    && Sunscreen_decrypt_correct
```

# Acknowledgements

None of the algorithms here are my own.  ChaCha20 and Poly1305 were
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

littleendian : [4][8] -> [32]
littleendian b = join(reverse b)
```

