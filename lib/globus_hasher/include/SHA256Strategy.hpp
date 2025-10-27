#ifndef _SHA256_STRATEGY_HPP_
#define _SHA256_STRATEGY_HPP_

#include "HashStrategy.hpp"

#include <irods/irods_error.hpp>

#include <boost/any.hpp>

#include <string>

namespace irods::globus {
    extern const std::string SHA256_NAME;
    class SHA256Strategy : public HashStrategy {
        public:
            SHA256Strategy() {};
            virtual ~SHA256Strategy() {};

            virtual std::string name() const override {
                return SHA256_NAME;
            }
            error init( boost::any& context ) const override;
            error update( const std::string& data, boost::any& context ) const override;
            error digest( std::string& messageDigest, boost::any& context ) const override;
            bool isChecksum( const std::string& ) const override;

    };
} // namespace irods::globus

#endif // _SHA256_STRATEGY_HPP_
