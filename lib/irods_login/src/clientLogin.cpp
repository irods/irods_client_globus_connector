#include "irods/authPluginRequest.h"
#include "irods/authentication_plugin_framework.hpp"
#include "irods/checksum.h"
#include "irods/irods_auth_constants.hpp"
#include "irods/irods_auth_factory.hpp"
#include "irods/irods_auth_manager.hpp"
#include "irods/irods_auth_object.hpp"
#include "irods/irods_auth_plugin.hpp"
#include "irods/irods_configuration_keywords.hpp"
#include "irods/irods_configuration_parser.hpp"
#include "irods/irods_environment_properties.hpp"
#include "irods/irods_kvp_string_parser.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_native_auth_object.hpp"
#include "irods/irods_pam_auth_object.hpp"
#include "irods/rcGlobalExtern.h"
#include "irods/rodsClient.h"
#include "irods/sslSockComm.h"
#include "irods/termiosUtil.hpp"
#include "irods/irods_plugin_context.hpp"

#include <openssl/md5.h>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/convenience.hpp>

#include <cerrno>
#include <string_view>
#include <functional>

#include <termios.h>

// This file is a modified copy of the clientLogin.cpp file from the iRODS core.  The 4.3.0 version
// of clientLogin() calls base64_decode() which resolves to a different version of the method in
// the globus environment.  This replicates clientLogin() but forces the use of the legacy login
// functionality which does not call base64_decode().  To make sure that this version of clientLogin()
// is being executed, the function was renamed to irods_globus_clientLogin().  In 4.3.1 the
// base64_encode/decode methods are placed in a namespace so there will no longer be ambiguities on
// the version.

//#pragma GCC diagnostic ignored "-Wregister"`
extern "C" {
  #include "globus_gridftp_server.h"
}

int printError( rcComm_t *Conn, int status, char *routineName ) {
    rError_t *Err;
    rErrMsg_t *ErrMsg;
    int i, len;
    if ( Conn ) {
        if ( Conn->rError ) {
            Err = Conn->rError;
            len = Err->len;
            for ( i = 0; i < len; i++ ) {
                ErrMsg = Err->errMsg[i];
                fprintf( stderr, "Level %d: %s\n", i, ErrMsg->msg );
            }
        }
    }
    char *mySubName = NULL;
    const char *myName = rodsErrorName( status, &mySubName );
    fprintf( stderr, "%s failed with error %d %s %s\n", routineName,
             status, myName, mySubName );
    free( mySubName );

    return 0;
}

/// =-=-=-=-=-=-=-
/// @brief irods_globus_clientLogin provides the interface for authentication
///        plugins as well as defining the protocol or template
///        Authentication will follow.  This is a modified copy of the clientLogin()
///        file from the iRODS core.  The 4.3.0 version of clientLogin() calls base64_decode()
///        which resolves to a different version of the method in the globus environment.
///        This replicates clientLogin() but forces the use of the legacy login functionality
///        which does not call base64_decode().  To make sure that this version of clientLogin()
///        is being executed, the function was renamed to irods_globus_clientLogin().
///        In 4.3.1 the base64_encode/decode methods are placed in a namespace so there will no
///        longer be ambiguities on the version and this will be deleted.
extern "C" {

    int irods_globus_clientLogin(rcComm_t* _comm, const char* _context, const char* _scheme_override)
    {
        if (!_comm) {
            return SYS_INVALID_INPUT_PARAM;
        }

        // If _comm already claims to be authenticated, there is nothing to do.
        if (1 == _comm->loggedIn) {
            return 0;
        }

        bool use_legacy_authentication = true;

        // =-=-=-=-=-=-=-
        // get the rods environment so we can determine the
        // flavor of authentication desired by the user -
        // check the environment variable first then the rods
        // env if that was null
        std::string auth_scheme = irods::AUTH_NATIVE_SCHEME;
        if ( ProcessType == CLIENT_PT ) {
            // =-=-=-=-=-=-=-
            // the caller may want to override the env var
            // or irods env file configuration ( PAM )
            if ( _scheme_override && strlen( _scheme_override ) > 0 ) {
                auth_scheme = _scheme_override;
            }
            else {
                // =-=-=-=-=-=-=-
                // check the environment variable first
                char* auth_env_var = getenv( irods::to_env( irods::KW_CFG_IRODS_AUTHENTICATION_SCHEME ).c_str() );
                if ( !auth_env_var ) {
                    rodsEnv rods_env;
                    if ( getRodsEnv( &rods_env ) >= 0 ) {
                        if ( strlen( rods_env.rodsAuthScheme ) > 0 ) {
                            auth_scheme = rods_env.rodsAuthScheme;
                        }
                    }
                }
                else {
                    auth_scheme = auth_env_var;
                }

                // =-=-=-=-=-=-=-
                // ensure scheme is lower case for comparison
                std::string lower_scheme = auth_scheme;
                std::transform( auth_scheme.begin(), auth_scheme.end(), auth_scheme.begin(), ::tolower );

                // =-=-=-=-=-=-=-
                // filter out the pam auth as it is an extra special
                // case and only sent in as an override.
                // everyone other scheme behaves as normal
                if (use_legacy_authentication && irods::AUTH_PAM_SCHEME == auth_scheme) {
                    auth_scheme = irods::AUTH_NATIVE_SCHEME;
                }
            } // if _scheme_override
        } // if client side auth

        // =-=-=-=-=-=-=-
        // construct an auth object given the scheme
        irods::auth_object_ptr auth_obj;
        irods::error ret = irods::auth_factory( auth_scheme, _comm->rError, auth_obj );
        if ( !ret.ok() ) {
            irods::log( PASS( ret ) );
            return ret.code();
        }

        // =-=-=-=-=-=-=-
        // resolve an auth plugin given the auth object
        irods::plugin_ptr ptr;
        ret = auth_obj->resolve( irods::AUTH_INTERFACE, ptr );
        if ( !ret.ok() ) {
            irods::log( PASS( ret ) );
            return ret.code();
        }
        irods::auth_ptr auth_plugin = boost::dynamic_pointer_cast< irods::auth >( ptr );

        // =-=-=-=-=-=-=-
        // call client side init
        ret = auth_plugin->call <rcComm_t*, const char* > ( NULL, irods::AUTH_CLIENT_START, auth_obj, _comm, _context );
        if ( !ret.ok() ) {
            irods::log( PASS( ret ) );
            return ret.code();
        }

        // =-=-=-=-=-=-=-
        // send an authentication request to the server
        ret = auth_plugin->call <rcComm_t* > ( NULL, irods::AUTH_CLIENT_AUTH_REQUEST, auth_obj, _comm );
        if ( !ret.ok() ) {
            printError(
                _comm,
                ret.code(),
                const_cast<char*>(ret.result().c_str()));
            return ret.code();
        }

        // =-=-=-=-=-=-=-
        // establish auth context client side
        ret = auth_plugin->call( NULL, irods::AUTH_ESTABLISH_CONTEXT, auth_obj );
        if ( !ret.ok() ) {
            irods::log( PASS( ret ) );
            return ret.code();
        }

        // =-=-=-=-=-=-=-
        // send the auth response to the agent
        ret = auth_plugin->call <rcComm_t* > ( NULL, irods::AUTH_CLIENT_AUTH_RESPONSE, auth_obj, _comm );
        if ( !ret.ok() ) {
            printError(
                _comm,
                ret.code(),
                const_cast<char*>(ret.result().c_str()));
            return ret.code();
        }

        // =-=-=-=-=-=-=-
        // set the flag stating we are logged in
        _comm->loggedIn = 1;

        // =-=-=-=-=-=-=-
        // win!
        return 0;

    } // irods_globus_clientLogin
}
