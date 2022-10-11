#ifndef IRODS_GLOBUS_BASE64_H__
#define IRODS_GLOBUS_BASE64_H__

namespace irods::globus {
    int base64_encode( const unsigned char *in,  unsigned long inlen,
                       unsigned char *out, unsigned long *outlen );
    int base64_decode( const unsigned char *in,  unsigned long inlen,
                       unsigned char *out, unsigned long *outlen );
}

#endif //IRODS_GLOBUS_BASE64_H__
