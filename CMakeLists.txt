##############################################################################
# Copyright (c) 2013 CINECA (www.hpc.cineca.it)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Globus DSI to manage data on iRODS.
#
# Author: Roberto Mucci - SCAI - CINECA
# Email:  hpc-service@cineca.it
#
###############################################################################

cmake_minimum_required (VERSION 3.11 FATAL_ERROR)

find_package(IRODS 4.3.3 EXACT REQUIRED CONFIG)
set(IRODS_CLIENT_REVISION "0")
set(IRODS_CLIENT_VERSION "${IRODS_VERSION}.${IRODS_CLIENT_REVISION}")

set(IRODS_CLIENT_NAME "irods-gridftp-client")

set(CMAKE_C_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang)
set(CMAKE_CXX_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang++)

include(GNUInstallDirs)

project (iRODS_DSI C CXX)

set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-nostdinc++)

##### Check ENV variables ######
if (DEFINED ENV{GLOBUS_LOCATION})
    message(STATUS "GLOBUS_LOCATION is defined as '$ENV{GLOBUS_LOCATION}'")
else()
    set(ENV{GLOBUS_LOCATION} "/usr")
    message(STATUS "Setting unspecified GLOBUS_LOCATION to '$ENV{GLOBUS_LOCATION}'. This is the correct setting for normal builds.")
endif()

if (DEFINED ENV{DEST_LIB_DIR})
    message(STATUS "DEST_LIB_DIR is defined as '$ENV{DEST_LIB_DIR}'")
else()
    if (IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "centos")
        set(ENV{DEST_LIB_DIR} "/usr/lib64")
    elseif(IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "ubuntu" OR IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "debian")
        set(ENV{DEST_LIB_DIR} "/usr/lib")
    else()
        set(ENV{DEST_LIB_DIR} "/usr/lib")
    endif()
    message(STATUS "Setting unspecified DEST_LIB_DIR to '$ENV{DEST_LIB_DIR}'. This is the correct setting for normal builds.")
endif()

if (DEFINED ENV{DEST_ETC_DIR})
    message(STATUS "DEST_ETC_DIR is defined as '$ENV{DEST_ETC_DIR}'")
else()
    set(ENV{DEST_ETC_DIR} "/etc/grid-security")
    message(STATUS "Setting unspecified DEST_ETC_DIR to '$ENV{DEST_ETC_DIR}'. This is the correct setting for normal builds.")
endif()

if (DEFINED ENV{DEST_BIN_DIR})
    message(STATUS "DEST_BIN_DIR is defined as '$ENV{DEST_BIN_DIR}'")
else()
    set(ENV{DEST_BIN_DIR} "/usr/bin")
    message(STATUS "Setting unspecified DEST_BIN_DIR to '$ENV{DEST_BIN_DIR}'. This is the correct setting for normal builds.")
endif()


##### iRODS #####
if (NOT IRODS_EXTERNALS_PACKAGE_ROOT)
  set(IRODS_EXTERNALS_PACKAGE_ROOT "/opt/irods-externals" CACHE STRING "Choose the location of iRODS external packages." FORCE)
  message(STATUS "Setting unspecified IRODS_EXTERNALS_PACKAGE_ROOT to '${IRODS_EXTERNALS_PACKAGE_ROOT}'. This is the correct setting for normal builds.")
endif()

macro(IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH DEPENDENCY_NAME DEPENDENCY_SUBDIRECTORY)
  if (IS_DIRECTORY ${IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME}})
    message(STATUS "Using user-specified value for IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME}: ${IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME}}")
  else()
    if (NOT IS_DIRECTORY ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY})
      message(FATAL_ERROR "${DEPENDENCY_NAME} not found at ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY}")
    endif()
    set(IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME} ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY})
  endif()
endmacro()

macro(IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH_ADD_TO_IRODS_PACKAGE_DEPENDENCIES_LIST DEPENDENCY_NAME DEPENDENCY_SUBDIRECTORY)
  IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH(${DEPENDENCY_NAME} ${DEPENDENCY_SUBDIRECTORY})
  list(APPEND IRODS_PACKAGE_DEPENDENCIES_LIST irods-externals-${DEPENDENCY_SUBDIRECTORY})
endmacro()
string(REPLACE ";" ", " IRODS_PACKAGE_DEPENDENCIES_STRING "${IRODS_PACKAGE_DEPENDENCIES_LIST}")
#################


FIND_PACKAGE(CURL)
IF(CURL_FOUND)
    INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR})
    SET(requiredlibs ${requiredlibs} ${CURL_LIBRARIES} )
ELSE(CURL_FOUND)
    MESSAGE(FATAL_ERROR "Could not find the CURL library and development files.")
ENDIF(CURL_FOUND)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
add_definitions(-DIRODS_HEADER_HPP -DOPENSSL_API_COMPAT=10100)

add_compile_options(-Wall -Wextra -Werror -Wno-unused-parameter)

remove_definitions(-DIRODS_HEADER_HPP)
add_definitions(-DIRODS_42)
set(irods_include_path_list
    ${IRODS_EXTERNALS_FULLPATH_CLANG}/include/c++/v1
    ${IRODS_INCLUDE_DIRS}
    ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
    ${IRODS_EXTERNALS_FULLPATH_JSON}/include
    ${IRODS_EXTERNALS_FULLPATH_FMT}/include
    )

set(irods_link_obj_path
    PRIVATE
    irods_client
    irods_common
    irods_plugin_dependencies
    "-lrt"
    "${IRODS_EXTERNALS_FULLPATH_AVRO}/lib/libavrocpp.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_thread.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
    "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
    "/${IRODS_PLUGINS_DIRECTORY}/network/libtcp_client.so"
    "/${IRODS_PLUGINS_DIRECTORY}/network/libssl_client.so"
    "/${IRODS_PLUGINS_DIRECTORY}/auth/libnative_client.so"
    )

if (CPACK_GENERATOR)
  message(STATUS "CPACK_GENERATOR is defined as '${CPACK_GENERATOR}'")
else()
  set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
  message(STATUS "Setting unspecified CPACK_GENERATOR to '${CPACK_GENERATOR}'. This is the correct setting for normal builds.")
endif()

message(STATUS "CMAKE_SYSTEM_PROCESSOR is '${CMAKE_SYSTEM_PROCESSOR}'")
if (CPACK_GENERATOR STREQUAL "RPM")
    set(IRODS_CLIENT_PACKAGE_FILE_NAME_SUFFIX "-${IRODS_CLIENT_VERSION}-1.${CMAKE_SYSTEM_PROCESSOR}")
elseif(CPACK_GENERATOR STREQUAL "DEB")
  set(IRODS_CLIENT_PACKAGE_FILE_NAME_SUFFIX "-${IRODS_CLIENT_VERSION}-${IRODS_LINUX_DISTRIBUTION_NAME}${IRODS_LINUX_DISTRIBUTION_VERSION_MAJOR}-${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(IRODS_CLIENT_PACKAGE_FILE_NAME_SUFFIX "-${IRODS_CLIENT_VERSION}-${IRODS_LINUX_DISTRIBUTION_NAME}${IRODS_LINUX_DISTRIBUTION_VERSION_MAJOR}-${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(CPACK_PACKAGE_FILE_NAME "${IRODS_CLIENT_NAME}${IRODS_CLIENT_PACKAGE_FILE_NAME_SUFFIX}")
message(STATUS "CPACK_PACKAGE_FILE_NAME is defined as '${CPACK_PACKAGE_FILE_NAME}'")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_PACKAGE_VERSION ${IRODS_CLIENT_VERSION})
set(CPACK_PACKAGE_CONTACT "Renaissance Computing Institute <info@irods.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The integrated Rule-Oriented Data System")
set(CPACK_PACKAGE_VENDOR "Renaissance Computing Institute <info@irods.org>")

set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_DEBIAN_PACKAGE_SECTION "contrib/science")
set(CPACK_DEBIAN_COMPRESSION_TYPE "gzip")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://irods.org")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)

set(CPACK_RPM_COMPONENT_INSTALL OFF)
set(CPACK_RPM_PACKAGE_RELEASE "1")
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_VENDOR "iRODS Consortium")
set(CPACK_RPM_PACKAGE_URL "https://irods.org")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)
set(CPACK_RPM_RELOCATION_PATHS $ENV{DEST_LIB_DIR})

set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

set(CPACK_DEBIAN_PACKAGE_NAME ${IRODS_CLIENT_NAME})

find_package(OpenSSL)
if (OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(STATUS "OPENSSL_VERSION < 3.0.0")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime (= ${IRODS_VERSION}), libc6, libssl1.1")
else()
    message(STATUS "OPENSSL_VERSION >= 3.0.0")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime (= ${IRODS_VERSION}), libc6, libssl3")
endif()

set(CPACK_RPM_PACKAGE_NAME ${IRODS_CLIENT_NAME})
if (IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "opensuse")
    set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime = ${IRODS_VERSION}, libopenssl1_0_0")
else()
    set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime = ${IRODS_VERSION}, openssl")
endif()

include(CPack)

if (DEFINED ENV{FLAVOR})
    message(STATUS "FLAVOR is defined as $ENV{FLAVOR}")
    set(dsi_library_name globus_gridftp_server_iRODS_$ENV{FLAVOR})
    set(gridmap_callout_library_name gridmap_iRODS_callout_$ENV{FLAVOR})
    set(gridmap_callout_library_LINK_FLAGS "-lglobus_gridmap_callout_error")
else()
    set(dsi_library_name globus_gridftp_server_iRODS)
    set(gridmap_callout_library_name gridmap_iRODS_callout)
    set(gridmap_callout_library_LINK_FLAGS "-lglobus_gridmap_callout_error")
endif()

#################################

message(STATUS "DSI library name will be '${dsi_library_name}'")
message(STATUS "Gridmap callout library name will be '${gridmap_callout_library_name}'")

add_library(${dsi_library_name} SHARED
    DSI/globus_gridftp_server_iRODS.cpp
    DSI/pid_manager.c external/cJSON.c
    ${CMAKE_SOURCE_DIR}/lib/globus_hasher/src/ADLER32Strategy.cpp
    ${CMAKE_SOURCE_DIR}/lib/globus_hasher/src/Hasher.cpp
    ${CMAKE_SOURCE_DIR}/lib/globus_hasher/src/MD5Strategy.cpp
    ${CMAKE_SOURCE_DIR}/lib/globus_hasher/src/SHA1Strategy.cpp
    ${CMAKE_SOURCE_DIR}/lib/globus_hasher/src/SHA256Strategy.cpp
    ${CMAKE_SOURCE_DIR}/lib/globus_hasher/src/SHA512Strategy.cpp
    ${CMAKE_SOURCE_DIR}/lib/globus_hasher/src/irods_hasher_factory.cpp
    )
add_library(${gridmap_callout_library_name} SHARED DSI/gridmap_iRODS_callout.c DSI/libirodsmap.c)

set_target_properties(${dsi_library_name} PROPERTIES VERSION ${IRODS_CLIENT_VERSION})
set_target_properties(${dsi_library_name} PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(${dsi_library_name} ${irods_link_obj_path} ${CURL_LIBRARIES})

set_target_properties(${gridmap_callout_library_name} PROPERTIES LINK_FLAGS ${gridmap_callout_library_LINK_FLAGS} VERSION ${IRODS_CLIENT_VERSION})
set_target_properties(${gridmap_callout_library_name} PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(${gridmap_callout_library_name} ${irods_link_obj_path} ${CURL_LIBRARIES})

set(gridmap_callout_conf_name gridmap_iRODS_callout.conf)

set(testirodsmap_exe "testirodsmap")
set(testirodsmap_exe_LINK_FLAGS "-ldl -lglobus_gss_assist -lstdc++")
add_executable(${testirodsmap_exe} DSI/testirodsmap.c DSI/libirodsmap.c)
set_target_properties(${testirodsmap_exe} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${testirodsmap_exe} PROPERTIES LINK_FLAGS ${testirodsmap_exe_LINK_FLAGS})
target_link_libraries(${testirodsmap_exe} ${irods_link_obj_path} ${CURL_LIBRARIES})

set(testpidmanager_exe "testpidmanager")
add_executable(${testpidmanager_exe} DSI/pid_manager_test.c DSI/pid_manager.c external/cJSON.c)
target_link_libraries(${testpidmanager_exe} ${irods_link_obj_path} "-lm -lglobus_gridftp_server" ${CURL_LIBRARIES})

include_directories(
    ${CMAKE_SOURCE_DIR}/lib/globus_hasher/include
    ${irods_include_path_list}
    )

include_directories(
        $ENV{GLOBUS_LOCATION}/include/globus
        $ENV{GLOBUS_LOCATION}/lib/globus/include
        $ENV{GLOBUS_LOCATION}/lib64/globus/include
        ${CURL_INCLUDE_DIR}
        DSI
        external)

if (DEFINED ENV{FLAVOR})
    include_directories($ENV{GLOBUS_LOCATION}/include/ENV{FLAVOR})
endif()

install(TARGETS ${dsi_library_name} ${gridmap_callout_library_name} DESTINATION $ENV{DEST_LIB_DIR})

install(TARGETS ${testirodsmap_exe} DESTINATION $ENV{DEST_BIN_DIR})
install(TARGETS ${testpidmanager_exe} DESTINATION $ENV{DEST_BIN_DIR})
configure_file(DSI/${gridmap_callout_conf_name}.in ${gridmap_callout_conf_name})
install(FILES ${PROJECT_BINARY_DIR}/${gridmap_callout_conf_name} DESTINATION $ENV{DEST_ETC_DIR})

