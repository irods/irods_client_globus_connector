#ifndef IRODS_GLOBUS_CLIENT_LOGIN_HPP
#define IRODS_GLOBUS_CLIENT_LOGIN_HPP

#include "irods/rodsDef.h"
#include "irods/rodsError.h"
#include "irods/rodsLog.h"
#include "irods/stringOpr.h"
#include "irods/rodsType.h"
#include "irods/rodsUser.h"
#include "irods/getRodsEnv.h"
#include "irods/objInfo.h"
#include "irods/dataObjInpOut.h"

#ifdef __cplusplus
extern "C" {
#endif

int
irods_globus_clientLogin( rcComm_t *conn, const char* _context, const char* _scheme_override );

#ifdef __cplusplus
}
#endif

#endif //IRODS_GLOBUS_CLIENT_LOGIN_HPP

