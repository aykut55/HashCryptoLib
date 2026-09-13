package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    @PREFIX
    @libdir
    @BINDIR @BINDIR_REL_PREFIX
    @LIBDIR @LIBDIR_REL_PREFIX
    @INCLUDEDIR @INCLUDEDIR_REL_PREFIX
    @APPLINKDIR @APPLINKDIR_REL_PREFIX
    @MODULESDIR @MODULESDIR_REL_LIBDIR
    @PKGCONFIGDIR @PKGCONFIGDIR_REL_LIBDIR
    @CMAKECONFIGDIR @CMAKECONFIGDIR_REL_LIBDIR
    $COMMENT $VERSION @LDLIBS
);

our $COMMENT                    = '';
our @PREFIX                     = ( 'D:\Aykut\HashCryptoLib\3rdParty\openssl402\_install\x64' );
our @libdir                     = ( 'D:\Aykut\HashCryptoLib\3rdParty\openssl402\_install\x64\lib' );
our @BINDIR                     = ( 'D:\Aykut\HashCryptoLib\3rdParty\openssl402\_install\x64\bin' );
our @BINDIR_REL_PREFIX          = ( 'bin' );
our @LIBDIR                     = ( 'D:\Aykut\HashCryptoLib\3rdParty\openssl402\_install\x64\lib' );
our @LIBDIR_REL_PREFIX          = ( 'lib' );
our @INCLUDEDIR                 = ( 'D:\Aykut\HashCryptoLib\3rdParty\openssl402\_install\x64\include' );
our @INCLUDEDIR_REL_PREFIX      = ( 'include' );
our @APPLINKDIR                 = ( 'D:\Aykut\HashCryptoLib\3rdParty\openssl402\_install\x64\include\openssl' );
our @APPLINKDIR_REL_PREFIX      = ( 'include/openssl' );
our @MODULESDIR                 = ( 'D:\Aykut\HashCryptoLib\3rdParty\openssl402\_install\x64\lib\ossl-modules' );
our @MODULESDIR_REL_LIBDIR      = ( 'ossl-modules' );
our @PKGCONFIGDIR               = ( 'D:\Aykut\HashCryptoLib\3rdParty\openssl402\_install\x64\lib' );
our @PKGCONFIGDIR_REL_LIBDIR    = ( '' );
our @CMAKECONFIGDIR             = ( 'D:\Aykut\HashCryptoLib\3rdParty\openssl402\_install\x64\lib\cmake\OpenSSL' );
our @CMAKECONFIGDIR_REL_LIBDIR  = ( 'cmake\OpenSSL' );
our $VERSION                    = '4.0.2';
our @LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    $^O eq 'VMS'
    ? split(/ *, */, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ')
    : split(/ +/, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ');

1;
