#ifndef IRODS_GLOBUS_CONNECTOR_HASHER_FACTORY_HPP
#define IRODS_GLOBUS_CONNECTOR_HASHER_FACTORY_HPP

#include "Hasher.hpp"

#include <irods/irods_error.hpp>

#include <string>

namespace irods::globus {

    error getHasher( const std::string& name, Hasher& hasher );
    error get_hash_scheme_from_checksum(
        const std::string& checksum,
        std::string& scheme );

}; // namespace irods::globus

#endif // IRODS_GLOBUS_CONNECTOR_HASHER_FACTORY_HPP
