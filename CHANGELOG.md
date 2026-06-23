# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project **only** adheres to the following _(as defined at [Semantic Versioning](https://semver.org/spec/v2.0.0.html))_:

> Given a version number MAJOR.MINOR.PATCH, increment the:
> 
> - MAJOR version when you make incompatible API changes
> - MINOR version when you add functionality in a backward compatible manner
> - PATCH version when you make backward compatible bug fixes

## [5.1.0] - 2026-06-24

This release cleans up the buildsystem, addresses build warnings, and adds a new configuration property for improving the performance of checksum calculations.

### Changed

- Clean up header includes (#43).
- Make CMake consistent with other iRODS projects (#74).
- Migrate to irods-provided hashers (#128).
- Replace variable length arrays with `alloca()` (#130).
- Migrate from Boost.Format to fmtlib (#132).
- Migrate some `std::stringstream` usage to fmtlib (#133).
- Migrate from cJSON to nlohmann-json (#134).
- Log more information during transfers (#141).

### Fixed

- Fix strict-protypes warning in pid_manager test (#129).
- Fix unused-parameter warnings (#131).
- Restore and use local hasher implementations for iRODS 5.0.2 or earlier (#140).

### Added

- Make buffer size for reading during checksum calculations configurable (#143).

## [5.0.1] - 2025-10-20

### Fixed

- Clear `dataObjCopyInp_t` struct to avoid segfault on rename operation (#124).
