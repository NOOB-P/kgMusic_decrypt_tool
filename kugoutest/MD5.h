/* MD5.H - header file for MD5C.C
 */

 /* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 rights reserved.

 License to copy and use this software is granted provided that it
 is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 Algorithm" in all material mentioning or referencing this software
 or this function.

 License is also granted to make and use derivative works provided
 that such works are identified as "derived from the RSA Data
 Security, Inc. MD5 Message-Digest Algorithm" in all material
 mentioning or referencing the derived work.

 RSA Data Security, Inc. makes no representations concerning either
 the merchantability of this software or the suitability of this
 software for any particular purpose. It is provided "as is"
 without express or implied warranty of any kind.

 These notices must be retained in any copies of any part of this
 documentation and/or software.
  */

  /* POINTER defines a generic pointer type */
typedef unsigned char* POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */

 /* MD5 context. */
typedef struct tagMD5_CTX {
	UINT4 state[4];                                   /* state (ABCD) */
	UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;
#ifdef __cplusplus
extern "C" {
#endif
	void MD5Init(MD5_CTX* context);
	void MD5Update(MD5_CTX* context, unsigned char* input, unsigned int inputLen);
	void MD5Final(unsigned char digest[16], MD5_CTX* context);

	static void MD5Transform(UINT4 state[4], unsigned char block[64]);
	static void Encode(unsigned char* output, UINT4* input, unsigned int len);
	static void Decode(UINT4* output, unsigned char* input, unsigned int len);
	static void MD5_memcpy(POINTER output, POINTER input, unsigned int len);
	static void MD5_memset(POINTER output, int value, unsigned int len);

#ifdef __cplusplus
}
#endif
