#ifndef IRODS_GLOBUS_CONNECTOR_CHECKSUM_HPP
#define IRODS_GLOBUS_CONNECTOR_CHECKSUM_HPP

#include <irods/objInfo.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_CHKSUM_PREFIX "sha2:"
#define SHA512_CHKSUM_PREFIX "sha512:"
#define ADLER32_CHKSUM_PREFIX "adler32:"
#define SHA1_CHKSUM_PREFIX "sha1:"
int verifyChksumLocFile( char *fileName, const char *myChksum, char *chksumStr );

int
chksumLocFile( const char *fileName, char *chksumStr, const char* );
int
hashToStr( unsigned char *digest, char *digestStr );
int
rcChksumLocFile( char *fileName, char *chksumFlag, keyValPair_t *condInput, const char* );

#ifdef __cplusplus
}
#endif

#endif	/* IRODS_GLOBUS_CONNECTOR_CHECKSUM_HPP */
