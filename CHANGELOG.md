# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added
- Added an ARMv7-ready DHCPv4 server with direct and relay support, configurable address allocation, and persistent leases and reservations.
- Added commands to check configuration and readiness, run the server, and manage reservations.
- Added startup checks for network interfaces, storage, and required system capabilities.
- Added setup, configuration, deployment, and end-to-end validation guides.
- Added end-to-end coverage for DHCP exchanges, relays, reservations, and persistence across restarts.
- Fixed correct DHCP lease ownership and reply delivery, validate daemon PIDs, verify ARM toolchain and io_uring ABI, and include the FeOxDB 32-bit overflow patch.
