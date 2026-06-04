#ifndef IRODS_GLOBUS_CONNECTOR_MD5_STRATEGY_HPP
#define IRODS_GLOBUS_CONNECTOR_MD5_STRATEGY_HPP

#include "HashStrategy.hpp"

#include <irods/irods_error.hpp>

#include <boost/any.hpp>

#include <string>

namespace irods::globus {
    extern const std::string MD5_NAME;
    class MD5Strategy : public HashStrategy {
        public:
            MD5Strategy() {};
            virtual ~MD5Strategy() {};

            std::string name() const override {
                return MD5_NAME;
            }
            error init( boost::any& context ) const override;
            error update( const std::string&, boost::any& context ) const override;
            error digest( std::string& messageDigest, boost::any& context ) const override;
            bool isChecksum( const std::string& ) const override;

    };
} // namespace irods::globus

#endif // IRODS_GLOBUS_CONNECTOR_MD5_STRATEGY_HPP
