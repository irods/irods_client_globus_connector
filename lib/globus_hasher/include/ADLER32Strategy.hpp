#ifndef _ADLER32_STRATEGY_HPP_
#define _ADLER32_STRATEGY_HPP_

#include "HashStrategy.hpp"

#include <irods/irods_error.hpp>

#include <boost/any.hpp>

#include <string>

namespace irods::globus {
    extern const std::string ADLER32_NAME;
    class ADLER32Strategy : public HashStrategy {
        public:
            ADLER32Strategy() {};
            virtual ~ADLER32Strategy() {};

            std::string name() const override {
                return ADLER32_NAME;
            }
            error init( boost::any& context ) const override;
            error update( const std::string& data, boost::any& context ) const override;
            error digest( std::string& messageDigest, boost::any& context ) const override;
            bool isChecksum( const std::string& ) const override;

    };
} // namespace irods::globus

#endif // _ADLER32_STRATEGY_HPP_
