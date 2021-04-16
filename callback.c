/*
 * File:   callback.c
 * Author: DoI
 *
 * This file defines a set of callback methods that can be used
 * to perform custom actions prior to, or after, sending a test
 * case. Relies on an -O3 compiler optimization to prune out the
 * calls if there is nothing defined in these methods.
 */


#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <endian.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define SHA256 SSLSHA256
#include <openssl/ssl.h>
#undef SHA256

#include "generator.h"

#define USER "administrator"
#define PASSWORD "aaptel-42"
#define UNC_PATH1 "\\\\192.168.2.110\\scratch"
#define UNC_PATH2 "\\\\192.168.2.110\\IPC$"

/*
  ############################################################################
  ##                         SHA  routines                                  ##
  ############################################################################
*/

/**************************** sha.h ****************************/
/******************* See RFC 4634 for details ******************/
#ifndef _SHA_H_
#define _SHA_H_

#ifndef USE_SHA1
  #define USE_SHA1 0
#endif

#ifndef USE_SHA224
  #define USE_SHA224 0
#endif

#ifndef USE_SHA384_SHA512
  #define USE_SHA384_SHA512 0
#endif

/*
 *  Description:
 *      This file implements the Secure Hash Signature Standard
 *      algorithms as defined in the National Institute of Standards
 *      and Technology Federal Information Processing Standards
 *      Publication (FIPS PUB) 180-1 published on April 17, 1995, 180-2
 *      published on August 1, 2002, and the FIPS PUB 180-2 Change
 *      Notice published on February 28, 2004.
 *
 *      A combined document showing all algorithms is available at
 *              http://csrc.nist.gov/publications/fips/
 *              fips180-2/fips180-2withchangenotice.pdf
 *
 *      The five hashes are defined in these sizes:
 *              SHA-1           20 byte / 160 bit
 *              SHA-224         28 byte / 224 bit
 *              SHA-256         32 byte / 256 bit
 *              SHA-384         48 byte / 384 bit
 *              SHA-512         64 byte / 512 bit
 */

/*
 * If you do not have the ISO standard stdint.h header file, then you
 * must typedef the following:
 *    name              meaning
 *  uint64_t         unsigned 64 bit integer
 *  uint32_t         unsigned 32 bit integer
 *  uint8_t          unsigned 8 bit integer (i.e., unsigned char)
 *  int_least16_t    integer of >= 16 bits
 *
 */

#ifndef _SHA_enum_
#define _SHA_enum_
/*
 *  All SHA functions return one of these values.
 */
enum
{
  shaSuccess = 0,
  shaNull,			/* Null pointer parameter */
  shaInputTooLong,		/* input data too long */
  shaStateError,		/* called Input after FinalBits or Result */
  shaBadParam			/* passed a bad parameter */
};
#endif /* _SHA_enum_ */

/*
 *  These constants hold size information for each of the SHA
 *  hashing operations
 */
enum
{
#if defined(USE_SHA1) && USE_SHA1
  SHA1_Message_Block_Size = 64,
  SHA1HashSize = 20,
  SHA1HashSizeBits = 160,
#endif
#if defined(USE_SHA224) && USE_SHA224
  SHA224_Message_Block_Size = 64,
  SHA224HashSize = 28,
  SHA224HashSizeBits = 224,
#endif
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
  SHA384_Message_Block_Size = 128,
  SHA384HashSize = 48,
  SHA384HashSizeBits = 384,
#endif
  SHA256_Message_Block_Size = 64,
  SHA512_Message_Block_Size = 128,
  USHA_Max_Message_Block_Size = SHA512_Message_Block_Size,

  SHA256HashSize = 32,
  SHA512HashSize = 64,
  USHAMaxHashSize = SHA512HashSize,

  SHA256HashSizeBits = 256,
  SHA512HashSizeBits = 512, USHAMaxHashSizeBits = SHA512HashSizeBits
};

/*
 *  These constants are used in the USHA (unified sha) functions.
 */
typedef enum SHAversion
{
#if defined(USE_SHA1) && USE_SHA1
  SHA1,
#endif
#if defined(USE_SHA224) && USE_SHA224
  SHA224,
#endif
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
  SHA384,
  SHA512,
#endif
  SHA256
} SHAversion;

#if defined(USE_SHA1) && USE_SHA1
/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation.
 */
typedef struct SHA1Context
{
  uint32_t Intermediate_Hash[SHA1HashSize / 4];	/* Message Digest */

  uint32_t Length_Low;		/* Message length in bits */
  uint32_t Length_High;		/* Message length in bits */

  int_least16_t Message_Block_Index;	/* Message_Block array index */
  /* 512-bit message blocks */
  uint8_t Message_Block[SHA1_Message_Block_Size];

  int Computed;			/* Is the digest computed? */
  int Corrupted;		/* Is the digest corrupted? */
} SHA1Context;
#endif

/*
 *  This structure will hold context information for the SHA-256
 *  hashing operation.
 */
typedef struct SHA256Context
{
  uint32_t Intermediate_Hash[SHA256HashSize / 4];	/* Message Digest */

  uint32_t Length_Low;		/* Message length in bits */
  uint32_t Length_High;		/* Message length in bits */

  int_least16_t Message_Block_Index;	/* Message_Block array index */
  /* 512-bit message blocks */
  uint8_t Message_Block[SHA256_Message_Block_Size];

  int Computed;			/* Is the digest computed? */
  int Corrupted;		/* Is the digest corrupted? */
} SHA256Context;

/*
 *  This structure will hold context information for the SHA-512
 *  hashing operation.
 */
typedef struct SHA512Context
{
#ifdef USE_32BIT_ONLY
  uint32_t Intermediate_Hash[SHA512HashSize / 4];	/* Message Digest  */
  uint32_t Length[4];		/* Message length in bits */
#else				/* !USE_32BIT_ONLY */
  uint64_t Intermediate_Hash[SHA512HashSize / 8];	/* Message Digest */
  uint64_t Length_Low, Length_High;	/* Message length in bits */
#endif				/* USE_32BIT_ONLY */
  int_least16_t Message_Block_Index;	/* Message_Block array index */
  /* 1024-bit message blocks */
  uint8_t Message_Block[SHA512_Message_Block_Size];

  int Computed;			/* Is the digest computed? */
  int Corrupted;		/* Is the digest corrupted? */
} SHA512Context;

#if defined(USE_SHA224) && USE_SHA224
/*
 *  This structure will hold context information for the SHA-224
 *  hashing operation. It uses the SHA-256 structure for computation.
 */
typedef struct SHA256Context SHA224Context;
#endif

#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
/*
 *  This structure will hold context information for the SHA-384
 *  hashing operation. It uses the SHA-512 structure for computation.
 */
typedef struct SHA512Context SHA384Context;
#endif

/*
 *  This structure holds context information for all SHA
 *  hashing operations.
 */
typedef struct USHAContext
{
  int whichSha;			/* which SHA is being used */
  union
  {
#if defined(USE_SHA1) && USE_SHA1
    SHA1Context sha1Context;
#endif
#if defined(USE_SHA224) && USE_SHA224
    SHA224Context sha224Context;
#endif
    SHA256Context sha256Context;
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
    SHA384Context sha384Context;
    SHA512Context sha512Context;
#endif
  } ctx;
} USHAContext;

/*
 *  This structure will hold context information for the HMAC
 *  keyed hashing operation.
 */
typedef struct HMACContext
{
  int whichSha;			/* which SHA is being used */
  int hashSize;			/* hash size of SHA being used */
  int blockSize;		/* block size of SHA being used */
  USHAContext shaContext;	/* SHA context */
  unsigned char k_opad[USHA_Max_Message_Block_Size];
  /* outer padding - key XORd with opad */
} HMACContext;

/*
 *  Function Prototypes
 */

#if defined(USE_SHA1) && USE_SHA1
/* SHA-1 */
extern int SHA1Reset (SHA1Context *);
extern int SHA1Input (SHA1Context *, const uint8_t * bytes,
		      unsigned int bytecount);
extern int SHA1FinalBits (SHA1Context *, const uint8_t bits,
			  unsigned int bitcount);
extern int SHA1Result (SHA1Context *, uint8_t Message_Digest[SHA1HashSize]);
#endif

#if defined(USE_SHA224) && USE_SHA224
/* SHA-224 */
extern int SHA224Reset (SHA224Context *);
extern int SHA224Input (SHA224Context *, const uint8_t * bytes,
			unsigned int bytecount);
extern int SHA224FinalBits (SHA224Context *, const uint8_t bits,
			    unsigned int bitcount);
extern int SHA224Result (SHA224Context *,
			 uint8_t Message_Digest[SHA224HashSize]);
#endif

/* SHA-256 */
extern int SHA256Reset (SHA256Context *);
extern int SHA256Input (SHA256Context *, const uint8_t * bytes,
			unsigned int bytecount);
extern int SHA256FinalBits (SHA256Context *, const uint8_t bits,
			    unsigned int bitcount);
extern int SHA256Result (SHA256Context *,
			 uint8_t Message_Digest[SHA256HashSize]);

#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
/* SHA-384 */
extern int SHA384Reset (SHA384Context *);
extern int SHA384Input (SHA384Context *, const uint8_t * bytes,
			unsigned int bytecount);
extern int SHA384FinalBits (SHA384Context *, const uint8_t bits,
			    unsigned int bitcount);
extern int SHA384Result (SHA384Context *,
			 uint8_t Message_Digest[SHA384HashSize]);

/* SHA-512 */
extern int SHA512Reset (SHA512Context *);
extern int SHA512Input (SHA512Context *, const uint8_t * bytes,
			unsigned int bytecount);
extern int SHA512FinalBits (SHA512Context *, const uint8_t bits,
			    unsigned int bitcount);
extern int SHA512Result (SHA512Context *,
			 uint8_t Message_Digest[SHA512HashSize]);
#endif

/* Unified SHA functions, chosen by whichSha */
extern int USHAReset (USHAContext *, SHAversion whichSha);
extern int USHAInput (USHAContext *,
		      const uint8_t * bytes, unsigned int bytecount);
extern int USHAFinalBits (USHAContext *,
			  const uint8_t bits, unsigned int bitcount);
extern int USHAResult (USHAContext *,
		       uint8_t Message_Digest[USHAMaxHashSize]);
extern int USHABlockSize (enum SHAversion whichSha);
extern int USHAHashSize (enum SHAversion whichSha);
extern int USHAHashSizeBits (enum SHAversion whichSha);

/*
 * HMAC Keyed-Hashing for Message Authentication, RFC2104,
 * for all SHAs.
 * This interface allows a fixed-length text input to be used.
 */
extern int hmac (SHAversion whichSha,	/* which SHA algorithm to use */
		 const unsigned char *text,	/* pointer to data stream */
		 int text_len,	/* length of data stream */
		 const unsigned char *key,	/* pointer to authentication key */
		 int key_len,	/* length of authentication key */
		 uint8_t digest[USHAMaxHashSize]);	/* caller digest to fill in */

/*
 * HMAC Keyed-Hashing for Message Authentication, RFC2104,
 * for all SHAs.
 * This interface allows any length of text input to be used.
 */
extern int hmacReset (HMACContext * ctx, enum SHAversion whichSha,
		      const unsigned char *key, int key_len);
extern int hmacInput (HMACContext * ctx, const unsigned char *text,
		      int text_len);

extern int hmacFinalBits (HMACContext * ctx, const uint8_t bits,
			  unsigned int bitcount);
extern int hmacResult (HMACContext * ctx, uint8_t digest[USHAMaxHashSize]);

#endif /* _SHA_H_ */

/*************************** sha224-256.c ***************************/
/********************* See RFC 4634 for details *********************/
/*
 * Description:
 *   This file implements the Secure Hash Signature Standard
 *   algorithms as defined in the National Institute of Standards
 *   and Technology Federal Information Processing Standards
 *   Publication (FIPS PUB) 180-1 published on April 17, 1995, 180-2
 *   published on August 1, 2002, and the FIPS PUB 180-2 Change
 *   Notice published on February 28, 2004.
 *
 *   A combined document showing all algorithms is available at
 *       http://csrc.nist.gov/publications/fips/
 *       fips180-2/fips180-2withchangenotice.pdf
 *
 *   The SHA-224 and SHA-256 algorithms produce 224-bit and 256-bit
 *   message digests for a given data stream. It should take about
 *   2**n steps to find a message with the same digest as a given
 *   message and 2**(n/2) to find any two messages with the same
 *   digest, when n is the digest size in bits. Therefore, this
 *   algorithm can serve as a means of providing a
 *   "fingerprint" for a message.
 *
 * Portability Issues:
 *   SHA-224 and SHA-256 are defined in terms of 32-bit "words".
 *   This code uses <stdint.h> (included via "sha.h") to define 32
 *   and 8 bit unsigned integer types. If your C compiler does not
 *   support 32 bit unsigned integers, this code is not
 *   appropriate.
 *
 * Caveats:
 *   SHA-224 and SHA-256 are designed to work with messages less
 *   than 2^64 bits long. This implementation uses SHA224/256Input()
 *   to hash the bits that are a multiple of the size of an 8-bit
 *   character, and then uses SHA224/256FinalBits() to hash the
 *   final few bits of the input.
 */


/*
 * These definitions are defined in FIPS-180-2, section 4.1.
 * Ch() and Maj() are defined identically in sections 4.1.1,
 * 4.1.2 and 4.1.3.
 *
 * The definitions used in FIPS-180-2 are as follows:
 */

#ifndef USE_MODIFIED_MACROS
#define SHA_Ch(x,y,z)        (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA_Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#else /* USE_MODIFIED_MACROS */
/*
 * The following definitions are equivalent and potentially faster.
 */

#define SHA_Ch(x, y, z)      (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)     (((x) & ((y) | (z))) | ((y) & (z)))
#endif /* USE_MODIFIED_MACROS */

#define SHA_Parity(x, y, z)  ((x) ^ (y) ^ (z))

/* Define the SHA shift, rotate left and rotate right macro */
#define SHA256_SHR(bits,word)      ((word) >> (bits))
#define SHA256_ROTL(bits,word)                         \
  (((word) << (bits)) | ((word) >> (32-(bits))))
#define SHA256_ROTR(bits,word)                         \
  (((word) >> (bits)) | ((word) << (32-(bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA256_SIGMA0(word)   \
  (SHA256_ROTR( 2,word) ^ SHA256_ROTR(13,word) ^ SHA256_ROTR(22,word))
#define SHA256_SIGMA1(word)   \
  (SHA256_ROTR( 6,word) ^ SHA256_ROTR(11,word) ^ SHA256_ROTR(25,word))
#define SHA256_sigma0(word)   \
  (SHA256_ROTR( 7,word) ^ SHA256_ROTR(18,word) ^ SHA256_SHR( 3,word))
#define SHA256_sigma1(word)   \
  (SHA256_ROTR(17,word) ^ SHA256_ROTR(19,word) ^ SHA256_SHR(10,word))

/*
 * add "length" to the length
 */
static uint32_t addTemp;

#define SHA224_256AddLength(context, length)               \
  (addTemp = (context)->Length_Low, (context)->Corrupted = \
    (((context)->Length_Low += (length)) < addTemp) &&     \
    (++(context)->Length_High == 0) ? 1 : 0)

/* Local Function Prototypes */
static void SHA224_256Finalize (SHA256Context * context, uint8_t Pad_Byte);
static void SHA224_256PadMessage (SHA256Context * context, uint8_t Pad_Byte);
static void SHA224_256ProcessMessageBlock (SHA256Context * context);
static int SHA224_256Reset (SHA256Context * context, uint32_t * H0);
static int SHA224_256ResultN (SHA256Context * context,
			      uint8_t Message_Digest[], int HashSize);

/* Initial Hash Values: FIPS-180-2 section 5.3.2 */
static uint32_t SHA256_H0[SHA256HashSize / 4] = {
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

#if defined(USE_SHA224) && USE_SHA224
/* Initial Hash Values: FIPS-180-2 Change Notice 1 */
static uint32_t SHA224_H0[SHA256HashSize / 4] = {
  0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
  0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
};

/*
 * SHA224Reset
 *
 * Description:
 *   This function will initialize the SHA384Context in preparation
 *   for computing a new SHA224 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *
 * Returns:
 *   sha Error Code.
 */
int
SHA224Reset (SHA224Context * context)
{
  return SHA224_256Reset (context, SHA224_H0);
}

/*
 * SHA224Input
 *
 * Description:
 *   This function accepts an array of octets as the next portion
 *   of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update
 *   message_array: [in]
 *     An array of characters representing the next portion of
 *     the message.
 *   length: [in]
 *     The length of the message in message_array
 *
 * Returns:
 *   sha Error Code.
 *
 */
int
SHA224Input (SHA224Context * context, const uint8_t * message_array,
	     unsigned int length)
{
  return SHA256Input (context, message_array, length);
}

/*
 * SHA224FinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte. (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int
SHA224FinalBits (SHA224Context * context,
		 const uint8_t message_bits, unsigned int length)
{
  return SHA256FinalBits (context, message_bits, length);
}

/*
 * SHA224Result
 *
 * Description:
 *   This function will return the 224-bit message
 *   digest into the Message_Digest array provided by the caller.
 *   NOTE: The first octet of hash is stored in the 0th element,
 *      the last octet of hash in the 28th element.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 */
int
SHA224Result (SHA224Context * context, uint8_t Message_Digest[SHA224HashSize])
{
  return SHA224_256ResultN (context, Message_Digest, SHA224HashSize);
}

#endif /* defined(USE_SHA224) && USE_SHA224 */

/*
 * SHA256Reset
 *
 * Description:
 *   This function will initialize the SHA256Context in preparation
 *   for computing a new SHA256 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *
 * Returns:
 *   sha Error Code.
 */
int
SHA256Reset (SHA256Context * context)
{
  return SHA224_256Reset (context, SHA256_H0);
}

/*
 * SHA256Input
 *
 * Description:
 *   This function accepts an array of octets as the next portion
 *   of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update
 *   message_array: [in]
 *     An array of characters representing the next portion of
 *     the message.
 *   length: [in]
 *     The length of the message in message_array
 *
 * Returns:
 *   sha Error Code.
 */
int
SHA256Input (SHA256Context * context, const uint8_t * message_array,
	     unsigned int length)
{
  if (!length)
    return shaSuccess;

  if (!context || !message_array)
    return shaNull;

  if (context->Computed)
    {
      context->Corrupted = shaStateError;
      return shaStateError;
    }

  if (context->Corrupted)
    return context->Corrupted;

  while (length-- && !context->Corrupted)
    {
      context->Message_Block[context->Message_Block_Index++] =
	(*message_array & 0xFF);

      if (!SHA224_256AddLength (context, 8) &&
	  (context->Message_Block_Index == SHA256_Message_Block_Size))
	SHA224_256ProcessMessageBlock (context);

      message_array++;
    }

  return shaSuccess;

}

/*
 * SHA256FinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte. (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int
SHA256FinalBits (SHA256Context * context,
		 const uint8_t message_bits, unsigned int length)
{
  uint8_t masks[8] = {
    /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
    /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
    /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
    /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
  };
  uint8_t markbit[8] = {
    /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
    /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
    /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
    /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
  };

  if (!length)
    return shaSuccess;

  if (!context)
    return shaNull;

  if ((context->Computed) || (length >= 8) || (length == 0))
    {
      context->Corrupted = shaStateError;
      return shaStateError;
    }

  if (context->Corrupted)
    return context->Corrupted;

  SHA224_256AddLength (context, length);
  SHA224_256Finalize (context, (uint8_t)
		      ((message_bits & masks[length]) | markbit[length]));

  return shaSuccess;
}

/*
 * SHA256Result
 *
 * Description:
 *   This function will return the 256-bit message
 *   digest into the Message_Digest array provided by the caller.
 *   NOTE: The first octet of hash is stored in the 0th element,
 *      the last octet of hash in the 32nd element.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 */
int
SHA256Result (SHA256Context * context, uint8_t Message_Digest[])
{
  return SHA224_256ResultN (context, Message_Digest, SHA256HashSize);
}

/*
 * SHA224_256Finalize
 *
 * Description:
 *   This helper function finishes off the digest calculations.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update
 *   Pad_Byte: [in]
 *     The last byte to add to the digest before the 0-padding
 *     and length. This will contain the last bits of the message
 *     followed by another single bit. If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   sha Error Code.
 */
static void
SHA224_256Finalize (SHA256Context * context, uint8_t Pad_Byte)
{
  int i;
  SHA224_256PadMessage (context, Pad_Byte);
  /* message may be sensitive, so clear it out */
  for (i = 0; i < SHA256_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;
  context->Length_Low = 0;	/* and clear length */
  context->Length_High = 0;
  context->Computed = 1;
}

/*
 * SHA224_256PadMessage
 *
 * Description:
 *   According to the standard, the message must be padded to an
 *   even 512 bits. The first padding bit must be a '1'. The
 *   last 64 bits represent the length of the original message.
 *   All bits in between should be 0. This helper function will pad
 *   the message according to those rules by filling the
 *   Message_Block array accordingly. When it returns, it can be
 *   assumed that the message digest has been computed.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to pad
 *   Pad_Byte: [in]
 *     The last byte to add to the digest before the 0-padding
 *     and length. This will contain the last bits of the message
 *     followed by another single bit. If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   Nothing.
 */
static void
SHA224_256PadMessage (SHA256Context * context, uint8_t Pad_Byte)
{
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length. If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA256_Message_Block_Size - 8))
    {
      context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
      while (context->Message_Block_Index < SHA256_Message_Block_Size)
	context->Message_Block[context->Message_Block_Index++] = 0;
      SHA224_256ProcessMessageBlock (context);
    }
  else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA256_Message_Block_Size - 8))
    context->Message_Block[context->Message_Block_Index++] = 0;

  /*
   * Store the message length as the last 8 octets
   */
  context->Message_Block[56] = (uint8_t) (context->Length_High >> 24);
  context->Message_Block[57] = (uint8_t) (context->Length_High >> 16);
  context->Message_Block[58] = (uint8_t) (context->Length_High >> 8);
  context->Message_Block[59] = (uint8_t) (context->Length_High);
  context->Message_Block[60] = (uint8_t) (context->Length_Low >> 24);
  context->Message_Block[61] = (uint8_t) (context->Length_Low >> 16);
  context->Message_Block[62] = (uint8_t) (context->Length_Low >> 8);
  context->Message_Block[63] = (uint8_t) (context->Length_Low);

  SHA224_256ProcessMessageBlock (context);
}

/*
 * SHA224_256ProcessMessageBlock
 *
 * Description:
 *   This function will process the next 512 bits of the message
 *   stored in the Message_Block array.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update
 *
 * Returns:
 *   Nothing.
 *
 * Comments:
 *   Many of the variable names in this code, especially the
 *   single character names, were used because those were the
 *   names used in the publication.
 */
static void
SHA224_256ProcessMessageBlock (SHA256Context * context)
{
  /* Constants defined in FIPS-180-2, section 4.2.2 */
  static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };
  int t, t4;			/* Loop counter */
  uint32_t temp1, temp2;	/* Temporary word value */
  uint32_t W[64];		/* Word sequence */
  uint32_t A, B, C, D, E, F, G, H;	/* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = t4 = 0; t < 16; t++, t4 += 4)
    W[t] = (((uint32_t) context->Message_Block[t4]) << 24) |
      (((uint32_t) context->Message_Block[t4 + 1]) << 16) |
      (((uint32_t) context->Message_Block[t4 + 2]) << 8) |
      (((uint32_t) context->Message_Block[t4 + 3]));

  for (t = 16; t < 64; t++)
    W[t] = SHA256_sigma1 (W[t - 2]) + W[t - 7] +
      SHA256_sigma0 (W[t - 15]) + W[t - 16];

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  F = context->Intermediate_Hash[5];
  G = context->Intermediate_Hash[6];
  H = context->Intermediate_Hash[7];

  for (t = 0; t < 64; t++)
    {
      temp1 = H + SHA256_SIGMA1 (E) + SHA_Ch (E, F, G) + K[t] + W[t];
      temp2 = SHA256_SIGMA0 (A) + SHA_Maj (A, B, C);
      H = G;
      G = F;
      F = E;
      E = D + temp1;
      D = C;
      C = B;
      B = A;
      A = temp1 + temp2;
    }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Intermediate_Hash[5] += F;
  context->Intermediate_Hash[6] += G;
  context->Intermediate_Hash[7] += H;

  context->Message_Block_Index = 0;
}

/*
 * SHA224_256Reset
 *
 * Description:
 *   This helper function will initialize the SHA256Context in
 *   preparation for computing a new SHA256 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *   H0
 *     The initial hash value to use.
 *
 * Returns:
 *   sha Error Code.
 */
static int
SHA224_256Reset (SHA256Context * context, uint32_t * H0)
{
  if (!context)
    return shaNull;

  context->Length_Low = 0;
  context->Length_High = 0;
  context->Message_Block_Index = 0;

  context->Intermediate_Hash[0] = H0[0];
  context->Intermediate_Hash[1] = H0[1];
  context->Intermediate_Hash[2] = H0[2];
  context->Intermediate_Hash[3] = H0[3];
  context->Intermediate_Hash[4] = H0[4];
  context->Intermediate_Hash[5] = H0[5];
  context->Intermediate_Hash[6] = H0[6];
  context->Intermediate_Hash[7] = H0[7];

  context->Computed = 0;
  context->Corrupted = 0;

  return shaSuccess;
}

/*
 * SHA224_256ResultN
 *
 * Description:
 *   This helper function will return the 224-bit or 256-bit message
 *   digest into the Message_Digest array provided by the caller.
 *   NOTE: The first octet of hash is stored in the 0th element,
 *      the last octet of hash in the 28th/32nd element.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest: [out]
 *     Where the digest is returned.
 *   HashSize: [in]
 *     The size of the hash, either 28 or 32.
 *
 * Returns:
 *   sha Error Code.
 */
static int
SHA224_256ResultN (SHA256Context * context,
		   uint8_t Message_Digest[], int HashSize)
{
  int i;

  if (!context || !Message_Digest)
    return shaNull;

  if (context->Corrupted)
    return context->Corrupted;

  if (!context->Computed)
    SHA224_256Finalize (context, 0x80);

  for (i = 0; i < HashSize; ++i)
    Message_Digest[i] = (uint8_t)
      (context->Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03)));

  return shaSuccess;
}

/*
  ############################################################################
  ##                         USHA  routines                                 ##
  ############################################################################
*/

/**************************** usha.c ****************************/
/******************** See RFC 4634 for details ******************/
/*
 *  Description:
 *     This file implements a unified interface to the SHA algorithms.
 */

/*
 *  USHAReset
 *
 *  Description:
 *      This function will initialize the SHA Context in preparation
 *      for computing a new SHA message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *      whichSha: [in]
 *          Selects which SHA reset to call
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
USHAReset (USHAContext * ctx, enum SHAversion whichSha)
{
  if (ctx)
    {
      ctx->whichSha = whichSha;
      switch (whichSha)
	{
#if defined(USE_SHA1) && USE_SHA1
	case SHA1:
	  return SHA1Reset ((SHA1Context *) & ctx->ctx);
#endif
#if defined(USE_SHA224) && USE_SHA224
	case SHA224:
	  return SHA224Reset ((SHA224Context *) & ctx->ctx);
#endif
	case SHA256:
	  return SHA256Reset ((SHA256Context *) & ctx->ctx);
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
	case SHA384:
	  return SHA384Reset ((SHA384Context *) & ctx->ctx);
	case SHA512:
	  return SHA512Reset ((SHA512Context *) & ctx->ctx);
#endif
	default:
	  return shaBadParam;
	}
    }
  else
    {
      return shaNull;
    }
}

/*
 *  USHAInput
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
USHAInput (USHAContext * ctx, const uint8_t * bytes, unsigned int bytecount)
{
  if (ctx)
    {
      switch (ctx->whichSha)
	{
#if defined(USE_SHA1) && USE_SHA1
	case SHA1:
	  return SHA1Input ((SHA1Context *) & ctx->ctx, bytes, bytecount);
#endif
#if defined(USE_SHA224) && USE_SHA224
	case SHA224:
	  return SHA224Input ((SHA224Context *) & ctx->ctx, bytes, bytecount);
#endif
	case SHA256:
	  return SHA256Input ((SHA256Context *) & ctx->ctx, bytes, bytecount);
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
	case SHA384:
	  return SHA384Input ((SHA384Context *) & ctx->ctx, bytes, bytecount);
	case SHA512:
	  return SHA512Input ((SHA512Context *) & ctx->ctx, bytes, bytecount);
#endif
	default:
	  return shaBadParam;
	}
    }
  else
    {
      return shaNull;
    }
}

/*
 * USHAFinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte. (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int
USHAFinalBits (USHAContext * ctx, const uint8_t bits, unsigned int bitcount)
{
  if (ctx)
    {
      switch (ctx->whichSha)
	{
#if defined(USE_SHA1) && USE_SHA1
	case SHA1:
	  return SHA1FinalBits ((SHA1Context *) & ctx->ctx, bits, bitcount);
#endif
#if defined(USE_SHA224) && USE_SHA224
	case SHA224:
	  return SHA224FinalBits ((SHA224Context *) & ctx->ctx, bits,
				  bitcount);
#endif
	case SHA256:
	  return SHA256FinalBits ((SHA256Context *) & ctx->ctx, bits,
				  bitcount);
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
	case SHA384:
	  return SHA384FinalBits ((SHA384Context *) & ctx->ctx, bits,
				  bitcount);
	case SHA512:
	  return SHA512FinalBits ((SHA512Context *) & ctx->ctx, bits,
				  bitcount);
#endif
	default:
	  return shaBadParam;
	}
    }
  else
    {
      return shaNull;
    }
}

/*
 * USHAResult
 *
 * Description:
 *   This function will return the 160-bit message digest into the
 *   Message_Digest array provided by the caller.
 *   NOTE: The first octet of hash is stored in the 0th element,
 *      the last octet of hash in the 19th element.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA-1 hash.
 *   Message_Digest: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int
USHAResult (USHAContext * ctx, uint8_t Message_Digest[USHAMaxHashSize])
{
  if (ctx)
    {
      switch (ctx->whichSha)
	{
#if defined(USE_SHA1) && USE_SHA1
	case SHA1:
	  return SHA1Result ((SHA1Context *) & ctx->ctx, Message_Digest);
#endif
#if defined(USE_SHA224) && USE_SHA224
	case SHA224:
	  return SHA224Result ((SHA224Context *) & ctx->ctx, Message_Digest);
#endif
	case SHA256:
	  return SHA256Result ((SHA256Context *) & ctx->ctx, Message_Digest);
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
	case SHA384:
	  return SHA384Result ((SHA384Context *) & ctx->ctx, Message_Digest);
	case SHA512:
	  return SHA512Result ((SHA512Context *) & ctx->ctx, Message_Digest);
#endif
	default:
	  return shaBadParam;
	}
    }
  else
    {
      return shaNull;
    }
}

/*
 * USHABlockSize
 *
 * Description:
 *   This function will return the blocksize for the given SHA
 *   algorithm.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   block size
 *
 */
int
USHABlockSize (enum SHAversion whichSha)
{
  switch (whichSha)
    {
#if defined(USE_SHA1) && USE_SHA1
    case SHA1:
      return SHA1_Message_Block_Size;
#endif
#if defined(USE_SHA224) && USE_SHA224
    case SHA224:
      return SHA224_Message_Block_Size;
#endif
    case SHA256:
      return SHA256_Message_Block_Size;
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
    case SHA384:
      return SHA384_Message_Block_Size;
    case SHA512:
      return SHA512_Message_Block_Size;
#endif
    default:
      return SHA512_Message_Block_Size;
    }
}

/*
 * USHAHashSize
 *
 * Description:
 *   This function will return the hashsize for the given SHA
 *   algorithm.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   hash size
 *
 */
int
USHAHashSize (enum SHAversion whichSha)
{
  switch (whichSha)
    {
#if defined(USE_SHA1) && USE_SHA1
    case SHA1:
      return SHA1HashSize;
#endif
#if defined(USE_SHA224) && USE_SHA224
    case SHA224:
      return SHA224HashSize;
#endif
    case SHA256:
      return SHA256HashSize;
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
    case SHA384:
      return SHA384HashSize;
    case SHA512:
      return SHA512HashSize;
#endif
    default:
      return SHA512HashSize;
    }
}

/*
 * USHAHashSizeBits
 *
 * Description:
 *   This function will return the hashsize for the given SHA
 *   algorithm, expressed in bits.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   hash size in bits
 *
 */
int
USHAHashSizeBits (enum SHAversion whichSha)
{
  switch (whichSha)
    {
#if defined(USE_SHA1) && USE_SHA1
    case SHA1:
      return SHA1HashSizeBits;
#endif
#if defined(USE_SHA224) && USE_SHA224
    case SHA224:
      return SHA224HashSizeBits;
#endif
    case SHA256:
      return SHA256HashSizeBits;
#if defined(USE_SHA384_SHA512) && USE_SHA384_SHA512
    case SHA384:
      return SHA384HashSizeBits;
    case SHA512:
      return SHA512HashSizeBits;
#endif
    default:
      return SHA512HashSizeBits;
    }
}

/*
  ############################################################################
  ##                         HMAC  routines                                 ##
  ############################################################################
*/

/**************************** hmac.c ****************************/
/******************** See RFC 4634 for details ******************/
/*
 *  Description:
 *      This file implements the HMAC algorithm (Keyed-Hashing for
 *      Message Authentication, RFC2104), expressed in terms of the
 *      various SHA algorithms.
 */


/*
 *  hmac
 *
 *  Description:
 *      This function will compute an HMAC message digest.
 *
 *  Parameters:
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      key: [in]
 *          The secret shared key.
 *      key_len: [in]
 *          The length of the secret shared key.
 *      message_array: [in]
 *          An array of characters representing the message.
 *      length: [in]
 *          The length of the message in message_array
 *      digest: [out]
 *          Where the digest is returned.
 *          NOTE: The length of the digest is determined by
 *              the value of whichSha.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
hmac (SHAversion whichSha, const unsigned char *text, int text_len,
      const unsigned char *key, int key_len, uint8_t digest[USHAMaxHashSize])
{
  HMACContext ctx;
  return hmacReset (&ctx, whichSha, key, key_len) ||
    hmacInput (&ctx, text, text_len) || hmacResult (&ctx, digest);
}

/*
 *  hmacReset
 *
 *  Description:
 *      This function will initialize the hmacContext in preparation
 *      for computing a new HMAC message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      key: [in]
 *          The secret shared key.
 *      key_len: [in]
 *          The length of the secret shared key.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
hmacReset (HMACContext * ctx, enum SHAversion whichSha,
	   const unsigned char *key, int key_len)
{
  int i, blocksize, hashsize;

  /* inner padding - key XORd with ipad */
  unsigned char k_ipad[USHA_Max_Message_Block_Size];

  /* temporary buffer when keylen > blocksize */
  unsigned char tempkey[USHAMaxHashSize];

  if (!ctx)
    return shaNull;

  blocksize = ctx->blockSize = USHABlockSize (whichSha);
  hashsize = ctx->hashSize = USHAHashSize (whichSha);

  ctx->whichSha = whichSha;

  /*
   * If key is longer than the hash blocksize,
   * reset it to key = HASH(key).
   */
  if (key_len > blocksize)
    {
      USHAContext tctx;
      int err = USHAReset (&tctx, whichSha) ||
	USHAInput (&tctx, key, key_len) || USHAResult (&tctx, tempkey);
      if (err != shaSuccess)
	return err;

      key = tempkey;
      key_len = hashsize;
    }

  /*
   * The HMAC transform looks like:
   *
   * SHA(K XOR opad, SHA(K XOR ipad, text))
   *
   * where K is an n byte key.
   * ipad is the byte 0x36 repeated blocksize times
   * opad is the byte 0x5c repeated blocksize times
   * and text is the data being protected.
   */

  /* store key into the pads, XOR'd with ipad and opad values */
  for (i = 0; i < key_len; i++)
    {
      k_ipad[i] = key[i] ^ 0x36;
      ctx->k_opad[i] = key[i] ^ 0x5c;
    }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for (; i < blocksize; i++)
    {
      k_ipad[i] = 0x36;
      ctx->k_opad[i] = 0x5c;
    }

  /* perform inner hash */
  /* init context for 1st pass */
  return USHAReset (&ctx->shaContext, whichSha) ||
    /* and start with inner pad */
    USHAInput (&ctx->shaContext, k_ipad, blocksize);
}

/*
 *  hmacInput
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The HMAC context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
hmacInput (HMACContext * ctx, const unsigned char *text, int text_len)
{
  if (!ctx)
    return shaNull;
  /* then text of datagram */
  return USHAInput (&ctx->shaContext, text, text_len);
}

/*
 * HMACFinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The HMAC context to update
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte. (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int
hmacFinalBits (HMACContext * ctx, const uint8_t bits, unsigned int bitcount)
{
  if (!ctx)
    return shaNull;
  /* then final bits of datagram */
  return USHAFinalBits (&ctx->shaContext, bits, bitcount);
}

/*
 * HMACResult
 *
 * Description:
 *   This function will return the N-byte message digest into the
 *   Message_Digest array provided by the caller.
 *   NOTE: The first octet of hash is stored in the 0th element,
 *      the last octet of hash in the Nth element.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the HMAC hash.
 *   digest: [out]
 *     Where the digest is returned.
 *   NOTE 2: The length of the hash is determined by the value of
 *      whichSha that was passed to hmacReset().
 *
 * Returns:
 *   sha Error Code.
 *
 */
int
hmacResult (HMACContext * ctx, uint8_t * digest)
{
  if (!ctx)
    return shaNull;

  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  return USHAResult (&ctx->shaContext, digest) ||
    /* perform outer SHA */
    /* init context for 2nd pass */
    USHAReset (&ctx->shaContext, ctx->whichSha) ||
    /* start with outer pad */
    USHAInput (&ctx->shaContext, ctx->k_opad, ctx->blockSize) ||
    /* then results of 1st hash */
    USHAInput (&ctx->shaContext, digest, ctx->hashSize) ||
    /* finish up 2nd pass */
    USHAResult (&ctx->shaContext, digest);
}

/*
  ############################################################################
  ##                         MD4  routines                                  ##
  ############################################################################
*/

typedef struct {
  uint32_t state[4];                                   /* state (ABCD) */
  uint32_t count[2];        /* number of bits, modulo 2^64 (lsb first) */
  uint8_t buffer[64];                         /* input buffer */
} MD4_CTX;

void MD4Init(MD4_CTX *);
void MD4Update(MD4_CTX *, uint8_t *, uint32_t);
void MD4Final(uint8_t [16], MD4_CTX *);

/* From RFC1320 */

/* MD4C.C - RSA Data Security, Inc., MD4 message-digest algorithm
 */

/* Copyright (C) 1990-2, RSA Data Security, Inc. All rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD4 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD4 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

/* Constants for MD4Transform routine.
 */
#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15

static void MD4Transform(uint32_t [4], uint8_t [64]);
static void MD4Encode(uint8_t *, uint32_t *, uint32_t);
static void MD4Decode(uint32_t *, uint8_t *, uint32_t);

static uint8_t PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G and H are basic MD4 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG and HH are transformations for rounds 1, 2 and 3 */
/* Rotation is separate from addition to prevent recomputation */

#define FF(a, b, c, d, x, s) { \
    (a) += F ((b), (c), (d)) + (x); \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define GG(a, b, c, d, x, s) { \
    (a) += G ((b), (c), (d)) + (x) + (uint32_t)0x5a827999; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define HH(a, b, c, d, x, s) { \
    (a) += H ((b), (c), (d)) + (x) + (uint32_t)0x6ed9eba1; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }

/* MD4 initialization. Begins an MD4 operation, writing a new context.
 */
void MD4Init (MD4_CTX *context)
{
  context->count[0] = context->count[1] = 0;

  /* Load magic initialization constants.
   */
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD4 block update operation. Continues an MD4 message-digest
     operation, processing another message block, and updating the
     context.
 */
void MD4Update (MD4_CTX *context, uint8_t *input, uint32_t inputLen)
{
  uint32_t i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (uint32_t)((context->count[0] >> 3) & 0x3F);
  /* Update number of bits */
  if ((context->count[0] += ((uint32_t)inputLen << 3))
      < ((uint32_t)inputLen << 3))
    context->count[1]++;
  context->count[1] += ((uint32_t)inputLen >> 29);

  partLen = 64 - index;

  /* Transform as many times as possible.
   */
  if (inputLen >= partLen) {
    memcpy(&context->buffer[index], input, partLen);
    MD4Transform (context->state, context->buffer);

    for (i = partLen; i + 63 < inputLen; i += 64)
      MD4Transform (context->state, &input[i]);

    index = 0;
  }
  else
    i = 0;

  /* Buffer remaining input */
  memcpy(&context->buffer[index], &input[i], inputLen-i);
}

/* MD4 finalization. Ends an MD4 message-digest operation, writing the
     the message digest and zeroizing the context.
 */
void MD4Final (uint8_t digest[16], MD4_CTX *context)
{
  uint8_t bits[8];
  uint32_t index, padLen;

  /* Save number of bits */
  MD4Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64.
   */
  index = (uint32_t)((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD4Update (context, PADDING, padLen);

  /* Append length (before padding) */
  MD4Update (context, bits, 8);
  /* Store state in digest */
  MD4Encode (digest, context->state, 16);

  /* Zeroize sensitive information.
   */
  memset(context, 0, sizeof(*context));
}

/* MD4 basic transformation. Transforms state based on block.
 */
static void MD4Transform (uint32_t state[4], uint8_t block[64])
{
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  MD4Decode (x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11); /* 1 */
  FF (d, a, b, c, x[ 1], S12); /* 2 */
  FF (c, d, a, b, x[ 2], S13); /* 3 */
  FF (b, c, d, a, x[ 3], S14); /* 4 */
  FF (a, b, c, d, x[ 4], S11); /* 5 */
  FF (d, a, b, c, x[ 5], S12); /* 6 */
  FF (c, d, a, b, x[ 6], S13); /* 7 */
  FF (b, c, d, a, x[ 7], S14); /* 8 */
  FF (a, b, c, d, x[ 8], S11); /* 9 */
  FF (d, a, b, c, x[ 9], S12); /* 10 */
  FF (c, d, a, b, x[10], S13); /* 11 */
  FF (b, c, d, a, x[11], S14); /* 12 */
  FF (a, b, c, d, x[12], S11); /* 13 */
  FF (d, a, b, c, x[13], S12); /* 14 */
  FF (c, d, a, b, x[14], S13); /* 15 */
  FF (b, c, d, a, x[15], S14); /* 16 */

  /* Round 2 */
  GG (a, b, c, d, x[ 0], S21); /* 17 */
  GG (d, a, b, c, x[ 4], S22); /* 18 */
  GG (c, d, a, b, x[ 8], S23); /* 19 */
  GG (b, c, d, a, x[12], S24); /* 20 */
  GG (a, b, c, d, x[ 1], S21); /* 21 */
  GG (d, a, b, c, x[ 5], S22); /* 22 */
  GG (c, d, a, b, x[ 9], S23); /* 23 */
  GG (b, c, d, a, x[13], S24); /* 24 */
  GG (a, b, c, d, x[ 2], S21); /* 25 */
  GG (d, a, b, c, x[ 6], S22); /* 26 */
  GG (c, d, a, b, x[10], S23); /* 27 */
  GG (b, c, d, a, x[14], S24); /* 28 */
  GG (a, b, c, d, x[ 3], S21); /* 29 */
  GG (d, a, b, c, x[ 7], S22); /* 30 */
  GG (c, d, a, b, x[11], S23); /* 31 */
  GG (b, c, d, a, x[15], S24); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 0], S31); /* 33 */
  HH (d, a, b, c, x[ 8], S32); /* 34 */
  HH (c, d, a, b, x[ 4], S33); /* 35 */
  HH (b, c, d, a, x[12], S34); /* 36 */
  HH (a, b, c, d, x[ 2], S31); /* 37 */
  HH (d, a, b, c, x[10], S32); /* 38 */
  HH (c, d, a, b, x[ 6], S33); /* 39 */
  HH (b, c, d, a, x[14], S34); /* 40 */
  HH (a, b, c, d, x[ 1], S31); /* 41 */
  HH (d, a, b, c, x[ 9], S32); /* 42 */
  HH (c, d, a, b, x[ 5], S33); /* 43 */
  HH (b, c, d, a, x[13], S34); /* 44 */
  HH (a, b, c, d, x[ 3], S31); /* 45 */
  HH (d, a, b, c, x[11], S32); /* 46 */
  HH (c, d, a, b, x[ 7], S33); /* 47 */
  HH (b, c, d, a, x[15], S34); /* 48 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  /* Zeroize sensitive information.
   */
  memset(x, 0, sizeof(x));
}

/* Encodes input (uint32_t) into output (uint8_t). Assumes len is
     a multiple of 4.
 */
static void MD4Encode (uint8_t *output, uint32_t *input, uint32_t len)
{
  uint32_t i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = (uint8_t)(input[i] & 0xff);
    output[j+1] = (uint8_t)((input[i] >> 8) & 0xff);
    output[j+2] = (uint8_t)((input[i] >> 16) & 0xff);
    output[j+3] = (uint8_t)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (uint8_t) into output (uint32_t). Assumes len is
     a multiple of 4.
 */
static void MD4Decode (uint32_t *output, uint8_t *input, uint32_t len)
{
  uint32_t i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j+1]) << 8) |
      (((uint32_t)input[j+2]) << 16) | (((uint32_t)input[j+3]) << 24);
}

#undef S11
#undef S12
#undef S13
#undef S14
#undef S21
#undef S22
#undef S23
#undef S24
#undef S31
#undef S32
#undef S33
#undef S34
#undef F
#undef G
#undef H
#undef ROTATE_LEFT
#undef FF
#undef GG
#undef HH

/*
  ############################################################################
  ##                         MD5  routines                                  ##
  ############################################################################
*/

#define byteSwap(buf,words)

struct MD5Context {
	uint32_t buf[4];
	uint32_t bytes[2];
	uint32_t in[16];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, uint8_t const *buf, unsigned len);
void MD5Final(uint8_t digest[16], struct MD5Context *context);
void MD5Transform(uint32_t buf[4], uint32_t const in[16]);

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void
MD5Init(struct MD5Context *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;

	ctx->bytes[0] = 0;
	ctx->bytes[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void
MD5Update(struct MD5Context *ctx, uint8_t const *buf, unsigned len)
{
	uint32_t t;

	/* Update byte count */

	t = ctx->bytes[0];
	if ((ctx->bytes[0] = t + len) < t)
		ctx->bytes[1]++;	/* Carry from low to high */

	t = 64 - (t & 0x3f);	/* Space available in ctx->in (at least 1) */
	if (t > len) {
		memcpy((uint8_t *)ctx->in + 64 - t, buf, len);
		return;
	}
	/* First chunk is an odd size */
	memcpy((uint8_t *)ctx->in + 64 - t, buf, t);
	byteSwap(ctx->in, 16);
	MD5Transform(ctx->buf, ctx->in);
	buf += t;
	len -= t;

	/* Process data in 64-byte chunks */
	while (len >= 64) {
		memcpy(ctx->in, buf, 64);
		byteSwap(ctx->in, 16);
		MD5Transform(ctx->buf, ctx->in);
		buf += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */
	memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void
MD5Final(uint8_t digest[16], struct MD5Context *ctx)
{
	int count = ctx->bytes[0] & 0x3f;	/* Number of bytes in ctx->in */
	uint8_t *p = (uint8_t *)ctx->in + count;

	/* Set the first char of padding to 0x80.  There is always room. */
	*p++ = 0x80;

	/* Bytes of padding needed to make 56 bytes (-8..55) */
	count = 56 - 1 - count;

	if (count < 0) {	/* Padding forces an extra block */
		memset(p, 0, count + 8);
		byteSwap(ctx->in, 16);
		MD5Transform(ctx->buf, ctx->in);
		p = (uint8_t *)ctx->in;
		count = 56;
	}
	memset(p, 0, count);
	byteSwap(ctx->in, 14);

	/* Append length in bits and transform */
	ctx->in[14] = ctx->bytes[0] << 3;
	ctx->in[15] = ctx->bytes[1] << 3 | ctx->bytes[0] >> 29;
	MD5Transform(ctx->buf, ctx->in);

	byteSwap(ctx->buf, 4);
	memcpy(digest, ctx->buf, 16);
	memset(ctx, 0, sizeof(*ctx));	/* In case it's sensitive */
}

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f,w,x,y,z,in,s) \
	 (w += f(x,y,z) + in, w = (w<<s | w>>(32-s)) + x)

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
void
MD5Transform(uint32_t buf[4], uint32_t const in[16])
{
	register uint32_t a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
	MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
	MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
	MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
	MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
	MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
	MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
	MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
	MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
	MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
	MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
	MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
	MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

/*
  ############################################################################
  ##                         HMAC-MD5 for smb2                              ##
  ############################################################################
*/

/*
 * unsigned char*  text;                pointer to data stream/
 * int             text_len;            length of data stream
 * unsigned char*  key;                 pointer to authentication key
 * int             key_len;             length of authentication key
 * caddr_t         digest;              caller digest to be filled in
 */
void
smb2_hmac_md5(unsigned char *text, int text_len, unsigned char *key, int key_len,
	 unsigned char *digest)
{
        struct MD5Context context;
        unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
        unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */
        unsigned char tk[16];
        int i;
        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64) {
		struct MD5Context tctx;

                MD5Init(&tctx);
                MD5Update(&tctx, key, key_len);
                MD5Final(tk, &tctx);

                key = tk;
                key_len = 16;
        }

        /*
         * the HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        bzero( k_ipad, sizeof k_ipad);
        bzero( k_opad, sizeof k_opad);
        bcopy( key, k_ipad, key_len);
        bcopy( key, k_opad, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner MD5
         */
        MD5Init(&context);                   /* init context for 1st
                                              * pass */
        MD5Update(&context, k_ipad, 64);     /* start with inner pad */
        MD5Update(&context, text, text_len); /* then text of datagram */
        MD5Final(digest, &context);          /* finish up 1st pass */
        /*
         * perform outer MD5
         */
        MD5Init(&context);                   /* init context for 2nd
                                              * pass */
        MD5Update(&context, k_opad, 64);     /* start with outer pad */
        MD5Update(&context, digest, 16);     /* then results of 1st
                                              * hash */
        MD5Final(digest, &context);          /* finish up 2nd pass */
}

#undef F1
#undef F2
#undef F3
#undef F4
#undef MD5STEP

/*
  ############################################################################
  ##                         UCS2 routines                                  ##
  ############################################################################
*/

struct ucs2 {
        int len;
        uint16_t val[1];
};

/* Count number of leading 1 bits in the char */
static int
count_leading_1(int c)
{
        int i = 0;
        while (c & 0x80) {
                i++;
                c <<= 1;
        }
        return i;
}

/* Validates that utf8 points to a valid utf8 codepoint.
 * Will update **utf8 to point at the next character in the string.
 * return 0 if the encoding is valid and
 * -1 if not.
 * If the encoding is valid the codepoint will be returned in *cp.
 */
static int
validate_utf8_cp(const char **utf8, uint16_t *cp)
{
        int c = *(*utf8)++;
        int l = count_leading_1(c);

        switch (l) {
        case 0:
                /* 7-bit ascii is always ok */
                *cp = c & 0x7f;
                return 0;
        case 1:
                /* 10.. .... can never start a new codepoint */
                return -1;
        case 2:
        case 3:
                *cp = c & 0x1f;
                /* 2 and 3 byte sequences must always be followed by exactly
                 * 1 or 2 chars matching 10.. ....
                 */
                while(--l) {
                        c = *(*utf8)++;
                        if (count_leading_1(c) != 1) {
                                return -1;
                        }
                        *cp <<= 6;
                        *cp |= (c & 0x3f);
                }
                return 0;
        }
        return -1;
}

/* Validate that the given string is properly formated UTF8.
 * Returns >=0 if valid UTF8 and -1 if not.
 */
static int
validate_utf8_str(const char *utf8)
{
        const char *u = utf8;
        int i = 0;
        uint16_t cp;

        while (*u) {
                if (validate_utf8_cp(&u, &cp) < 0) {
                        return -1;
                }
                i++;
        }
        return i;
}

/* Convert a UTF8 string into UCS2 Little Endian */
struct ucs2 *
utf8_to_ucs2(const char *utf8)
{
        struct ucs2 *ucs2;
        int i, len;

        len = validate_utf8_str(utf8);
        if (len < 0) {
                return NULL;
        }

        ucs2 = malloc(offsetof(struct ucs2, val) + 2 * len);
        if (ucs2 == NULL) {
                return NULL;
        }

        ucs2->len = len;
        for (i = 0; i < len; i++) {
                validate_utf8_cp(&utf8, &ucs2->val[i]);
                ucs2->val[i] = htole32(ucs2->val[i]);
        }

        return ucs2;
}

/* Returns how many bytes we need to store a UCS2 codepoint
 */
static int
ucs2_cp_size(uint16_t cp)
{
        if (cp > 0x07ff) {
                return 3;
        }
        if (cp > 0x007f) {
                return 2;
        }
        return 1;
}

/*
 * Convert a UCS2 string into UTF8
 */
const char *
ucs2_to_utf8(const uint16_t *ucs2, int ucs2_len)
{
        int i, utf8_len = 1;
        char *str, *tmp;

        /* How many bytes do we need for utf8 ? */
        for (i = 0; i < ucs2_len; i++) {
                utf8_len += ucs2_cp_size(ucs2[i]);
        }
        str = tmp = malloc(utf8_len);
        if (str == NULL) {
                return NULL;
        }
        str[utf8_len - 1] = 0;

        for (i = 0; i < ucs2_len; i++) {
                uint16_t c = le32toh(ucs2[i]);
                int l = ucs2_cp_size(c);

                switch (l) {
                case 3:
                        *tmp++ = 0xe0 |  (c >> 12);
                        *tmp++ = 0x80 | ((c >>  6) & 0xbf);
                        *tmp++ = 0x80 | ((c      ) & 0xbf);
                        break;
                case 2:
                        *tmp++ = 0xc0 |  (c >> 6);
                        *tmp++ = 0x80 | ((c     ) & 0xbf);
                        break;
                case 1:
                        *tmp++ = c;
                        break;
                }
        }

        return str;
}

/*
  ############################################################################
  ##                         NTLMSSP                                        ##
  ############################################################################
*/

#define SMB2_SIGNATURE_SIZE 16
#define SMB2_KEY_SIZE 16

struct auth_data;

struct auth_data *
ntlmssp_init_context(const char *user,
                     const char *password,
                     const char *domain,
                     const char *workstation,
                     const char *client_challenge);

int
ntlmssp_generate_blob(int seal, time_t t,
                      struct auth_data *auth_data,
                      unsigned char *input_buf, int input_len,
                      unsigned char **output_buf, uint16_t *output_len);

void
ntlmssp_destroy_context(struct auth_data *auth);

int ntlmssp_get_session_key(struct auth_data *auth, uint8_t **key, uint8_t *key_size);

struct auth_data {
        unsigned char *buf;
        int len;
        int allocated;

        int neg_result;
        unsigned char *ntlm_buf;
        int ntlm_len;

        const char *user;
        const char *password;
        const char *domain;
        const char *workstation;
        const char *client_challenge;

        uint8_t exported_session_key[SMB2_KEY_SIZE];
};

#define NEGOTIATE_MESSAGE      0x00000001
#define CHALLENGE_MESSAGE      0x00000002
#define AUTHENTICATION_MESSAGE 0x00000003

#define NTLMSSP_NEGOTIATE_56                               0x80000000
#define NTLMSSP_NEGOTIATE_128                              0x20000000
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY         0x00080000
#define NTLMSSP_TARGET_TYPE_SERVER                         0x00020000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN                      0x00008000
#define NTLMSSP_NEGOTIATE_ANONYMOUS                        0x00000800
#define NTLMSSP_NEGOTIATE_NTLM                             0x00000200
#define NTLMSSP_NEGOTIATE_SEAL                             0x00000020
#define NTLMSSP_NEGOTIATE_SIGN                             0x00000010
#define NTLMSSP_REQUEST_TARGET                             0x00000004
#define NTLMSSP_NEGOTIATE_OEM                              0x00000002
#define NTLMSSP_NEGOTIATE_UNICODE                          0x00000001
#define NTLMSSP_NEGOTIATE_KEY_EXCH                         0x40000000

struct smb2_timeval {
        uint32_t tv_sec;
        uint32_t tv_usec;
};

/* Convert a win timestamp to a unix timeval */
void win_to_timeval(uint64_t smb2_time, struct smb2_timeval *tv);

/* Covnert unit timeval to a win timestamp */
uint64_t timeval_to_win(struct smb2_timeval *tv);

void
ntlmssp_destroy_context(struct auth_data *auth)
{
	if (!auth)
		return;
	free(auth->ntlm_buf);
	free(auth->buf);
	free(auth);
}

struct auth_data *
ntlmssp_init_context(const char *user,
                     const char *password,
                     const char *domain,
                     const char *workstation,
                     const char *client_challenge)
{
        struct auth_data *auth_data = NULL;

        auth_data = calloc(1, sizeof(struct auth_data));
        if (auth_data == NULL) {
                return NULL;
        }

        auth_data->user        = user;
        auth_data->password    = password;
        auth_data->domain      = domain;
        auth_data->workstation = workstation;
        auth_data->client_challenge = client_challenge;

        memset(auth_data->exported_session_key, 0, SMB2_KEY_SIZE);

        return auth_data;
}

static int
encoder(const void *buffer, size_t size, void *ptr)
{
        struct auth_data *auth_data = ptr;

        if (size + auth_data->len > auth_data->allocated) {
                unsigned char *tmp = auth_data->buf;

                auth_data->allocated = 2 * ((size + auth_data->allocated + 256) & ~0xff);
                auth_data->buf = malloc(auth_data->allocated);
                if (auth_data->buf == NULL) {
                        free(tmp);
                        return -1;
                }
                memcpy(auth_data->buf, tmp, auth_data->len);
                free(tmp);
        }

        memcpy(auth_data->buf + auth_data->len, buffer, size);
        auth_data->len += size;

        return 0;
}

static int
ntlm_negotiate_message(int seal, struct auth_data *auth_data)
{
        unsigned char ntlm[32];
        uint32_t u32;

        memset(ntlm, 0, 32);
        memcpy(ntlm, "NTLMSSP", 8);

        u32 = htole32(NEGOTIATE_MESSAGE);
        memcpy(&ntlm[8], &u32, 4);

        u32 = NTLMSSP_NEGOTIATE_56|NTLMSSP_NEGOTIATE_128|
                NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|
                //NTLMSSP_NEGOTIATE_ALWAYS_SIGN|
                NTLMSSP_NEGOTIATE_NTLM|
                //NTLMSSP_NEGOTIATE_SIGN|
                NTLMSSP_REQUEST_TARGET|NTLMSSP_NEGOTIATE_OEM|
                NTLMSSP_NEGOTIATE_UNICODE;
        if (seal)
                u32 |= NTLMSSP_NEGOTIATE_SEAL;
        u32 = htole32(u32);
        memcpy(&ntlm[12], &u32, 4);

        if (encoder(&ntlm[0], 32, auth_data) < 0) {
                return -1;
        }

        return 0;
}

static int
ntlm_challenge_message(struct auth_data *auth_data, unsigned char *buf,
                       int len)
{
        free(auth_data->ntlm_buf);
        auth_data->ntlm_len = len;
        auth_data->ntlm_buf = malloc(auth_data->ntlm_len);
        if (auth_data->ntlm_buf == NULL) {
                return -1;
        }
        memcpy(auth_data->ntlm_buf, buf, auth_data->ntlm_len);

        return 0;
}

static int
NTOWFv1(const char *password, unsigned char password_hash[16])
{
        MD4_CTX ctx;
        struct ucs2 *ucs2_password = NULL;

        ucs2_password = utf8_to_ucs2(password);
        if (ucs2_password == NULL) {
                return -1;
        }
        MD4Init(&ctx);
        MD4Update(&ctx, (unsigned char *)ucs2_password->val, ucs2_password->len * 2);
        MD4Final(password_hash, &ctx);
        free(ucs2_password);

        return 0;
}

static int
NTOWFv2(const char *user, const char *password, const char *domain,
        unsigned char ntlmv2_hash[16])
{
        int i, len;
        char *userdomain;
        struct ucs2 *ucs2_userdomain = NULL;
        unsigned char ntlm_hash[16];

        if (NTOWFv1(password, ntlm_hash) < 0) {
                return -1;
        }

        len = strlen(user) + 1;
        if (domain) {
                len += strlen(domain);
        }
        userdomain = malloc(len);
        if (userdomain == NULL) {
                return -1;
        }

        strcpy(userdomain, user);
        for (i = strlen(userdomain) - 1; i >=0; i--) {
                if (islower((unsigned int) userdomain[i])) {
                        userdomain[i] = toupper((unsigned int) userdomain[i]);
                }
        }
        if (domain) {
                strcat(userdomain, domain);
        }

        ucs2_userdomain = utf8_to_ucs2(userdomain);
        if (ucs2_userdomain == NULL) {
                free(userdomain);
                return -1;
        }

        smb2_hmac_md5((unsigned char *)ucs2_userdomain->val,
                 ucs2_userdomain->len * 2,
                 ntlm_hash, 16, ntlmv2_hash);
        free(userdomain);
        free(ucs2_userdomain);

        return 0;
}

/* This is not the same temp as in MS-NLMP. This temp has an additional
 * 16 bytes at the start of the buffer.
 * Use &auth_data->val[16] if you want the temp from MS-NLMP
 */
static int
encode_temp(struct auth_data *auth_data, uint64_t t, char *client_challenge,
            char *server_challenge, char *server_name, int server_name_len)
{
        unsigned char sign[8] = {0x01, 0x01, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00};
        unsigned char zero[8] = {0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00};

        if (encoder(&zero, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(server_challenge, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(sign, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(&t, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(client_challenge, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(&zero, 4, auth_data) < 0) {
                return -1;
        }
        if (encoder(server_name, server_name_len, auth_data) < 0) {
                return -1;
        }
        if (encoder(&zero, 4, auth_data) < 0) {
                return -1;
        }

        return 0;
}

static int
encode_ntlm_auth(int seal, time_t ti,
                 struct auth_data *auth_data, char *server_challenge)
{
        int ret = -1;
        unsigned char lm_buf[16];
        unsigned char *NTChallengeResponse_buf = NULL;
        unsigned char ResponseKeyNT[16];
        struct ucs2 *ucs2_domain = NULL;
        struct ucs2 *ucs2_user = NULL;
        struct ucs2 *ucs2_workstation = NULL;
        int NTChallengeResponse_len = 0;
        unsigned char NTProofStr[16];
        unsigned char LMStr[16];
        uint64_t t;
        struct smb2_timeval tv;
        char *server_name_buf;
        int server_name_len;
        uint32_t u32;
        uint32_t server_neg_flags;
        unsigned char key_exch[SMB2_KEY_SIZE];
        uint8_t anonymous = 0;

        tv.tv_sec = ti;
        tv.tv_usec = 0;
        t = timeval_to_win(&tv);

        if (auth_data->password == NULL) {
                anonymous = 1;
                goto encode;
        }

        /*
         * Generate Concatenation of(NTProofStr, temp)
         */
        if (NTOWFv2(auth_data->user, auth_data->password,
                    auth_data->domain, ResponseKeyNT)
            < 0) {
                goto finished;
        }

        /* get the server neg flags */
        memcpy(&server_neg_flags, &auth_data->ntlm_buf[20], 4);
        server_neg_flags = le32toh(server_neg_flags);

        memcpy(&u32, &auth_data->ntlm_buf[40], 4);
        u32 = le32toh(u32);
        server_name_len = u32 >> 16;

        memcpy(&u32, &auth_data->ntlm_buf[44], 4);
        u32 = le32toh(u32);
        server_name_buf = (char *)&auth_data->ntlm_buf[u32];

        if (encode_temp(auth_data, t, (char *)auth_data->client_challenge,
                        server_challenge, server_name_buf,
                        server_name_len) < 0) {
                return -1;
        }

        smb2_hmac_md5(&auth_data->buf[8], auth_data->len-8,
                 ResponseKeyNT, 16, NTProofStr);
        memcpy(auth_data->buf, NTProofStr, 16);

        NTChallengeResponse_buf = auth_data->buf;
        NTChallengeResponse_len = auth_data->len;
        auth_data->buf = NULL;
        auth_data->len = 0;
        auth_data->allocated = 0;

        /* get the NTLMv2 Key-Exchange Key
           For NTLMv2 - Key Exchange Key is the Session Base Key
         */
        smb2_hmac_md5(NTProofStr, 16, ResponseKeyNT, 16, key_exch);
        memcpy(auth_data->exported_session_key, key_exch, 16);

 encode:
        /*
         * Generate AUTHENTICATE_MESSAGE
         */
        encoder("NTLMSSP", 8, auth_data);

        /* message type */
        u32 = htole32(AUTHENTICATION_MESSAGE);
        encoder(&u32, 4, auth_data);

        /* lm challenge response fields */
        if (!anonymous) {
                memcpy(&lm_buf[0], server_challenge, 8);
                memcpy(&lm_buf[8], auth_data->client_challenge, 8);
                smb2_hmac_md5(&lm_buf[0], 16,
                              ResponseKeyNT, 16, LMStr);
                u32 = htole32(0x00180018);
                encoder(&u32, 4, auth_data);
                u32 = 0;
                encoder(&u32, 4, auth_data);
        } else {
                u32 = 0;
                encoder(&u32, 4, auth_data);
                encoder(&u32, 4, auth_data);
        }

        /* nt challenge response fields */
        u32 = htole32((NTChallengeResponse_len<<16)|
                      NTChallengeResponse_len);
        encoder(&u32, 4, auth_data);
        u32 = 0;
        encoder(&u32, 4, auth_data);

        /* domain name fields */
        if (!anonymous && auth_data->domain) {
                ucs2_domain = utf8_to_ucs2(auth_data->domain);
                if (ucs2_domain == NULL) {
                        goto finished;
                }
                u32 = ucs2_domain->len * 2;
                u32 = htole32((u32 << 16) | u32);
                encoder(&u32, 4, auth_data);
                u32 = 0;
                encoder(&u32, 4, auth_data);
        } else {
                u32 = 0;
                encoder(&u32, 4, auth_data);
                encoder(&u32, 4, auth_data);
        }

        /* user name fields */
        if (!anonymous) {
                ucs2_user = utf8_to_ucs2(auth_data->user);
                if (ucs2_user == NULL) {
                        goto finished;
                }
                u32 = ucs2_user->len * 2;
                u32 = htole32((u32 << 16) | u32);
                encoder(&u32, 4, auth_data);
                u32 = 0;
                encoder(&u32, 4, auth_data);
        } else {
                u32 = 0;
                encoder(&u32, 4, auth_data);
                encoder(&u32, 4, auth_data);
        }

        /* workstation name fields */
        if (!anonymous && auth_data->workstation) {
                ucs2_workstation = utf8_to_ucs2(auth_data->workstation);
                if (ucs2_workstation == NULL) {
                        goto finished;
                }
                u32 = ucs2_workstation->len * 2;
                u32 = htole32((u32 << 16) | u32);
                encoder(&u32, 4, auth_data);
                u32 = 0;
                encoder(&u32, 4, auth_data);
        } else {
                u32 = 0;
                encoder(&u32, 4, auth_data);
                encoder(&u32, 4, auth_data);
        }

        /* encrypted random session key */
        u32 = 0;
        encoder(&u32, 4, auth_data);
        encoder(&u32, 4, auth_data);

        /* negotiate flags */
        u32 = NTLMSSP_NEGOTIATE_56|NTLMSSP_NEGOTIATE_128|
                NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|
                //NTLMSSP_NEGOTIATE_ALWAYS_SIGN|
                NTLMSSP_NEGOTIATE_NTLM|
                //NTLMSSP_NEGOTIATE_SIGN|
                NTLMSSP_REQUEST_TARGET|NTLMSSP_NEGOTIATE_OEM|
                NTLMSSP_NEGOTIATE_UNICODE;
        if (anonymous)
                u32 |= NTLMSSP_NEGOTIATE_ANONYMOUS;
        if (seal)
                u32 |= NTLMSSP_NEGOTIATE_SEAL;
        u32 = htole32(u32);
        encoder(&u32, 4, auth_data);

        if (!anonymous) {
                /* append domain */
                u32 = htole32(auth_data->len);
                memcpy(&auth_data->buf[32], &u32, 4);
                if (ucs2_domain) {
                        encoder(ucs2_domain->val, ucs2_domain->len * 2,
                                auth_data);
                }

                /* append user */
                u32 = htole32(auth_data->len);
                memcpy(&auth_data->buf[40], &u32, 4);
                encoder(ucs2_user->val, ucs2_user->len * 2, auth_data);

                /* append workstation */
                u32 = htole32(auth_data->len);
                memcpy(&auth_data->buf[48], &u32, 4);
                if (ucs2_workstation) {
                        encoder(ucs2_workstation->val,
                                ucs2_workstation->len * 2, auth_data);
                }

                /* append LMChallengeResponse */
                u32 = htole32(auth_data->len);
                memcpy(&auth_data->buf[16], &u32, 4);
                encoder(LMStr, 16, auth_data);
                encoder(auth_data->client_challenge, 8, auth_data);

                /* append NTChallengeResponse */
                u32 = htole32(auth_data->len);
                memcpy(&auth_data->buf[24], &u32, 4);
                encoder(NTChallengeResponse_buf, NTChallengeResponse_len,
                        auth_data);
        }

        ret = 0;
finished:
        free(ucs2_domain);
        free(ucs2_user);
        free(ucs2_workstation);
        free(NTChallengeResponse_buf);

        return ret;
}

int
ntlmssp_generate_blob(int seal, time_t t,
                      struct auth_data *auth_data,
                      unsigned char *input_buf, int input_len,
                      unsigned char **output_buf, uint16_t *output_len)
{
        free(auth_data->buf);
        auth_data->buf = NULL;
        auth_data->len = 0;
        auth_data->allocated = 0;

        if (input_buf == NULL) {
                ntlm_negotiate_message(seal, auth_data);
        } else {
                if (ntlm_challenge_message(auth_data, input_buf,
                                           input_len) < 0) {
                        return -1;
                }
                if (encode_ntlm_auth(seal, t, auth_data,
                                     (char *)&auth_data->ntlm_buf[24]) < 0) {
                        return -1;
                }
        }

        *output_buf = auth_data->buf;
        *output_len = auth_data->len;

        return 0;
}

int
ntlmssp_get_session_key(struct auth_data *auth,
                        uint8_t **key,
                        uint8_t *key_size)
{
        uint8_t *mkey = NULL;

        if (auth == NULL || key == NULL || key_size == NULL) {
                return -1;
        }

        mkey = malloc(SMB2_KEY_SIZE);
        if (mkey == NULL) {
                return -1;
        }
        memcpy(mkey, auth->exported_session_key, SMB2_KEY_SIZE);

        *key = mkey;
        *key_size = SMB2_KEY_SIZE;

        return 0;
}

uint64_t
timeval_to_win(struct smb2_timeval *tv)
{
        return ((uint64_t)tv->tv_sec * 10000000) +
                116444736000000000 + tv->tv_usec * 10;
}

void
win_to_timeval(uint64_t smb2_time, struct smb2_timeval *tv)
{
        tv->tv_usec = (smb2_time / 10) % 1000000;
        tv->tv_sec  = (smb2_time - 116444736000000000) / 10000000;
}


/*
  ############################################################################
  ##                  SMB2 routines                                         ##
  ############################################################################
*/


#define SMB2_TIMEOUT 20000

#define SMB2_CMD_NEGPROT  0x0000
#define SMB2_CMD_SESSETUP 0x0001
#define SMB2_CMD_TREECON  0x0003

#define SMB2_NEGOTIATE_SIGNING_ENABLED 0x0001

#define NT_STATUS_SUCCESS 0x00000000
#define NT_STATUS_MOREPRO 0xc0000016
#define NT_STATUS_LOGON_FAILURE 0xc000006d


struct buf {
    size_t size;
    uint8_t p[1024];
};

#define PUSH_FUNC(name, type, pre)                      \
    static void push_ ## name (struct buf *b, type v) { \
        assert(b->size+sizeof(v) <= sizeof(b->p));      \
        pre;                                            \
        memcpy(b->p + b->size, &v, sizeof(v));          \
        b->size += sizeof(v);                           \
    }

PUSH_FUNC(u8,   uint8_t, (void)0);
PUSH_FUNC(le16, uint16_t, v=htole16(v));
PUSH_FUNC(le32, uint32_t, v=htole32(v));
PUSH_FUNC(le64, uint64_t, v=htole64(v));
//PUSH_FUNC(be16, uint16_t, v=htobe16(v));
PUSH_FUNC(be32, uint32_t, v=htobe32(v));
//PUSH_FUNC(be64, uint64_t, v=htobe64(v));

static void push_buf(struct buf *b, void *p, size_t len)
{
    assert(b->size+len <= sizeof(b->p));
    memcpy(b->p + b->size, p, len);
    b->size += len;
}

struct smb2_state {
    size_t msg_id;
    uint64_t session_id;
    uint32_t tree_id;
    struct auth_data *auth_data;
    struct buf *in_buf;
    struct buf *out_buf;
    int sock;
};

static void
smb2_prepend_length(struct buf *b)
{
    uint32_t nbt_len = htobe32(b->size - 4);
    memcpy(b->p, &nbt_len, sizeof(uint32_t));
}

static void
smb2_sign(struct smb2_state *smb2)
{
    HMACContext ctx;
    uint8_t digest[USHAMaxHashSize];
    int i;
    uint8_t *signature = smb2->out_buf->p + 4 + 48;
    uint32_t *flags = (uint32_t*)(smb2->out_buf->p + 4 + 16);

    memset(signature, 0, SMB2_SIGNATURE_SIZE);

    hmacReset(&ctx, SHA256, smb2->auth_data->exported_session_key, SMB2_KEY_SIZE);
    hmacInput(&ctx,
              smb2->out_buf->p + 4,
              smb2->out_buf->size - 4);
    hmacResult(&ctx, digest);
    memcpy(&signature[0], digest, SMB2_SIGNATURE_SIZE);
    *flags = *flags|htole32(1 << 3);
}

static void smb2_push_header(struct smb2_state *smb2, int cmd, int cred_charge, int cred_req)
{
    push_be32(smb2->out_buf,  0); // NetBios size, overwritten later
    push_be32(smb2->out_buf,  0xFE534d42); // ProtocolID
    push_le16(smb2->out_buf, 64); // StructureSize
    push_le16(smb2->out_buf,  cred_charge); // CreditCharge
    push_le32(smb2->out_buf,  0); // Status
    push_le16(smb2->out_buf,  cmd); // Command
    push_le16(smb2->out_buf,  cred_req); // CreditRequested
    push_le32(smb2->out_buf,  0); // Flags
    push_le32(smb2->out_buf,  0); // NextCommand
    push_le64(smb2->out_buf,  smb2->msg_id++); // MessageId
    push_le32(smb2->out_buf,  0); // Reserved
    push_le32(smb2->out_buf,  smb2->tree_id); // TreeId
    push_le64(smb2->out_buf,  smb2->session_id); // SessionId
    push_le64(smb2->out_buf,  0); // Signature (16 bytes)
    push_le64(smb2->out_buf,  0); // Signature
}

static void smb2_push_negprot_req(struct smb2_state *smb2)
{
    smb2->out_buf->size = 0;
    smb2_push_header(smb2, SMB2_CMD_NEGPROT, 0, 10);

    push_le16(smb2->out_buf, 36); // StructureSize
    push_le16(smb2->out_buf,  1); // DialectCount
    push_le16(smb2->out_buf, SMB2_NEGOTIATE_SIGNING_ENABLED); // SecurityMode
    push_le16(smb2->out_buf,  0); // Reserved
    push_le32(smb2->out_buf,  0); // Capabilities
    for (int i = 0; i < 16; i++) {
        push_u8(smb2->out_buf,  rand()%256); // ClientGuid
    }
    push_le64(smb2->out_buf,  0); // ClientStartTime
    push_le16(smb2->out_buf,  0x0202); // Dialect

    smb2_prepend_length(smb2->out_buf);
}

static void smb2_push_sessetup_req(struct smb2_state *smb2, uint8_t *in_sec_buf, uint16_t in_sec_len)
{
    uint8_t *sec_buf;
    uint16_t sec_len;
    uint16_t *sec_off;

    smb2->out_buf->size = 0;

    if (!in_sec_buf) {
        smb2->auth_data = ntlmssp_init_context(USER, PASSWORD, "", "", "abcdefgh");
    }
    ntlmssp_generate_blob(0, time(NULL), smb2->auth_data, in_sec_buf, in_sec_len, &sec_buf, &sec_len);

    smb2_push_header(smb2, SMB2_CMD_SESSETUP, 0, 130);

    push_le16(smb2->out_buf, 25); // StructureSize
    push_u8(smb2->out_buf,    0); // Flags
    push_u8(smb2->out_buf,    0); // SecurityMode
    push_le32(smb2->out_buf,  0); // Capabilities
    push_le32(smb2->out_buf,  0); // Channel
    push_le16(smb2->out_buf,  0); // SecurityBufferOffset
    sec_off = (uint16_t*)(smb2->out_buf->p + smb2->out_buf->size - 2);
    push_le16(smb2->out_buf, sec_len); // SecurityBufferLength
    push_le64(smb2->out_buf,  0); // PreviousSessionId
    *sec_off = htole16(smb2->out_buf->size - 4);
    push_buf(smb2->out_buf, sec_buf, sec_len);

    smb2_prepend_length(smb2->out_buf);
}

static void smb2_push_tcon_req(struct smb2_state *smb2, const char *name)
{
    uint16_t *path_off, *path_len, *path;

    smb2->out_buf->size = 0;

    smb2_push_header(smb2, SMB2_CMD_TREECON, 1, 64);

    push_le16(smb2->out_buf,  9); // StructureSize
    push_le16(smb2->out_buf,  0); // Flags
    path_off = (uint16_t*)(smb2->out_buf->p + smb2->out_buf->size);
    push_le16(smb2->out_buf,  0); // PathOffset (fill later)
    path_len = (uint16_t*)(smb2->out_buf->p + smb2->out_buf->size);
    push_le16(smb2->out_buf,  0); // PathLen (fill later)
    path = (uint16_t*)(smb2->out_buf->p + smb2->out_buf->size);
    struct ucs2 *ucs2 = utf8_to_ucs2(name);
    push_buf(smb2->out_buf, ucs2->val, ucs2->len*2);
    //push_le16(smb2->out_buf, 0);

    *path_off = htole16(((void*)path - (void*)smb2->out_buf->p) - 4);
    *path_len = htole16(ucs2->len*2);

    smb2_prepend_length(smb2->out_buf);
    free(ucs2);
}

static uint32_t smb2_get_status(struct smb2_state *smb2)
{
    assert(smb2->in_buf->size >= 4 + 4 + 2 + 2 + 4);
    uint32_t *p = (uint32_t*)(smb2->in_buf->p + 4 + 4 + 2 + 2);
    return le32toh(*p);
}

static void smb2_get_sessetup_sec_buf(struct smb2_state *smb2, uint8_t **buf, uint16_t *len)
{
    uint8_t *start = smb2->in_buf->p + 4;
    uint8_t *rsp = start + 64;
    uint16_t *sec_off = (uint16_t *)(rsp + 2 + 2);
    uint16_t *sec_len = (uint16_t *)(rsp + 2 + 2 + 2);
    *buf = (uint8_t*)(start + le16toh(*sec_off));
    *len = le16toh(*sec_len);
}

static uint64_t smb2_get_ses_id(struct smb2_state *smb2)
{
    uint8_t *start = smb2->in_buf->p + 4;
    return le64toh(*((uint64_t*)(start+4+2+2+4+2+2+4+4+8+4+4)));
}

static int smb2_send(struct smb2_state *smb2)
{
    return send(smb2->sock, smb2->out_buf->p, smb2->out_buf->size, 0);
}

static int smb2_recv(struct smb2_state *smb2)
{
    ssize_t rc;
    size_t min_size = 4;

    smb2->in_buf->size = 0;


    while (smb2->in_buf->size < min_size) {
        assert(smb2->in_buf->size < sizeof(smb2->in_buf->p));

        rc = recv(smb2->sock, smb2->in_buf->p, sizeof(smb2->in_buf->p) - smb2->in_buf->size, 0);
        if (rc < 0)
            return rc;
        if (rc == 0)
            break;
        smb2->in_buf->size += rc;
        if (min_size == 4 && smb2->in_buf->size >= 4) {
            min_size += (0x00ffffff & be32toh(*((uint32_t*)smb2->in_buf->p)));
        }
    }

    return rc >= 0 && min_size > 4 && smb2->in_buf->size == min_size;
}


// Called after the socket is connected but before the test case is sent.
void callback_pre_send(int sock, testcase_t * testcase){
    uint8_t *sec_buf;
    uint16_t sec_buf_len;
    struct buf in, out;
    struct smb2_state smb2 = {
        .sock = sock,
        .in_buf = &in,
        .out_buf = &out,
    };

    smb2_push_negprot_req(&smb2);
    smb2_send(&smb2);
    if (!smb2_recv(&smb2)) {
        printf("[E] couldnt do NEGPROT\n");
        goto out;
    }
    smb2.session_id = smb2_get_ses_id(&smb2);

    // 1st leg - get ntlm challenge
    smb2_push_sessetup_req(&smb2, NULL, 0);
    smb2_send(&smb2);
    if (!smb2_recv(&smb2)) {
        printf("[E] couldnt do SESS_SETUP #1\n");
        goto out;
    }
    smb2.session_id = smb2_get_ses_id(&smb2);
    smb2_get_sessetup_sec_buf(&smb2, &sec_buf, &sec_buf_len);

    // 2nd leg - send solved challenge
    smb2_push_sessetup_req(&smb2, sec_buf, sec_buf_len);
    smb2_send(&smb2);
    if (!smb2_recv(&smb2)) {
        printf("[E] couldnt do SESS_SETUP #2\n");
        goto out;
    }
    if (smb2_get_status(&smb2) != NT_STATUS_SUCCESS) {
        printf("[E] SESS_SETUP failed (login/pw?)\n");
        goto out;
    }

    // Tree con
    smb2_push_tcon_req(&smb2, UNC_PATH2);
    smb2_sign(&smb2);
    smb2_send(&smb2);
    if (!smb2_recv(&smb2)) {
        printf("[E] couldnt do TCON\n");
        goto out;
    }
    if (smb2_get_status(&smb2) != NT_STATUS_SUCCESS) {
        printf("[E] TCON failed\n");
        goto out;
    }

    // Tree con
    smb2_push_tcon_req(&smb2, UNC_PATH2);
    smb2_sign(&smb2);
    smb2_send(&smb2);
    if (!smb2_recv(&smb2)) {
        printf("[E] couldnt do TCON\n");
        goto out;
    }
    if (smb2_get_status(&smb2) != NT_STATUS_SUCCESS) {
        printf("[E] TCON failed\n");
        goto out;
    }


    printf("OK\n");

out:
    ntlmssp_destroy_context(smb2.auth_data);
}

// Called after the testcase is sent but before the socket is closed.
void callback_post_send(int sock){

}

void callback_ssl_pre_send(SSL * ssl, testcase_t * testcase){

}

void callback_ssl_post_send(SSL * ssl){

}
