#ifndef IRODS_GLOBUS_CONNECTOR_HASHER_HPP
#define IRODS_GLOBUS_CONNECTOR_HASHER_HPP

#include "HashStrategy.hpp"

#include <irods/irods_error.hpp>

#include <boost/any.hpp>

#include <string>

namespace irods::globus {

    const std::string STRICT_HASH_POLICY( "strict" );
    const std::string COMPATIBLE_HASH_POLICY( "compatible" );

    class Hasher {
        public:
            Hasher() : _strategy( NULL ) {}

            error init( const HashStrategy* );
            error update( const std::string& );
            error digest( std::string& messageDigest );

        private:
            const HashStrategy* _strategy;
            boost::any          _context;
            error               _stored_error;
            std::string         _stored_digest;
    };

}; // namespace irods::globus

#endif // IRODS_GLOBUS_CONNECTOR_HASHER_HPP
