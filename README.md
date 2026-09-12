  # CryptoAPI

  CryptoAPI is an extensible C++ cryptography SDK for Windows, providing encryption, hashing, digital signatures,
  certificate management, TLS, SSH, and integration through DLL and static libraries.

  > **Naming note:** The project name was changed from `HashCryptoLib` to `CryptoAPI`. The name `CryptoAPI` will be used throughout the project.

  > **Project status:** Planning and early development. The public API and features may change.

  ## Planned Features

  - AES encryption and decryption
  - SHA-2 hashing
  - HMAC and key derivation
  - Digital signing and verification
  - Cryptographically secure random number generation
  - X.509 certificate management
  - TLS client and server support
  - SSH and SFTP support
  - File, folder, stream, string and byte operations
  - Synchronous and asynchronous operations
  - Progress events and cancellation
  - Provider support for Windows CNG, OpenSSL, Crypto++, Botan and custom implementations

  ## Integration Options

  CryptoAPI is planned to support:

  - C++ classes
  - Versioned C API
  - Dynamic library (`DLL`)
  - Static library (`LIB`)
  - DLL and static library runners
  - Command-line application

  ## Platform Support

  - Windows 32-bit and 64-bit
  - Microsoft Visual Studio 2022 and later
  - Embarcadero C++Builder 10 and later

  Support is confirmed only for compiler and platform combinations that have passed the compatibility test suite.

  ## Architecture

  The SDK uses a provider-based architecture. Applications use a common API while cryptographic operations can be
  supplied by different backends.

  The first provider will use Windows Cryptography API: Next Generation (`CNG`).

  Planned providers include:

  - Windows CNG
  - OpenSSL
  - Crypto++
  - Botan
  - Custom C++ implementations

  ## Security

  CryptoAPI aims to provide secure defaults:

  - Authenticated encryption with AES-GCM
  - System-provided cryptographic random generation
  - Explicit algorithm and key policies
  - No silent fallback to obsolete algorithms
  - Authenticated decryption before output commit
  - Protected handling of keys and passwords

  This project has not yet completed an independent security audit. Do not use development versions in production
  systems.

  ## Documentation

  The architecture and implementation roadmap are available in [plan.md](plan.md).

  API documentation, format specifications and usage examples will be added as development progresses.

  ## Contributing

  Issues, design feedback and pull requests are welcome. Please discuss major API or architecture changes in an issue
  before implementation.

  ## License

  CryptoAPI is licensed under the [Apache License 2.0](LICENSE).
