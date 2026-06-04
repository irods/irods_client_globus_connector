#ifndef IRODS_GLOBUS_CONNECTOR_SHA1_STRATEGY_HPP
#define IRODS_GLOBUS_CONNECTOR_SHA1_STRATEGY_HPP

#include "HashStrategy.hpp"

#include <irods/irods_error.hpp>

#include <boost/any.hpp>

#include <string>

namespace irods::globus {
    extern const std::string SHA1_NAME;
    class SHA1Strategy : public HashStrategy {
        public:
            SHA1Strategy() {};
            virtual ~SHA1Strategy() {};

            std::string name() const override {
                return SHA1_NAME;
            }
            error init( boost::any& context ) const override;
            error update( const std::string& data, boost::any& context ) const override;
            error digest( std::string& messageDigest, boost::any& context ) const override;
            bool isChecksum( const std::string& ) const override;

    };
} // namespace irods::globus

#endif // IRODS_GLOBUS_CONNECTOR_SHA1_STRATEGY_HPP
