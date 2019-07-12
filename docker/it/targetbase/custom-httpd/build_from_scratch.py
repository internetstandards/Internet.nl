#!/usr/bin/env python
""" Base script to successively build Zlib, OpenSSL and nassl from scratch.

It will build the _nassl C extension for the python interpreter/platform that was used to run this script (ie. no
cross-compiling).
"""
from __future__ import absolute_import
from __future__ import unicode_literals
import os
import sys
import shutil
from abc import ABCMeta

from setup import MODERN_OPENSSL_LIB_INSTALL_PATH, CURRENT_PLATFORM, SupportedPlatformEnum, \
    MODERN_OPENSSL_HEADERS_INSTALL_PATH, LEGACY_OPENSSL_LIB_INSTALL_PATH, LEGACY_OPENSSL_HEADERS_INSTALL_PATH, \
    ZLIB_LIB_INSTALL_PATH, SHOULD_BUILD_FOR_DEBUG
from os import getcwd
from os.path import join
import subprocess

# The build script expects the OpenSSL and Zlib src packages to be in nassl's root folder
# Warning: use a fresh Zlib src tree on Windows or build will fail ie. do not use the same Zlib src folder for Windows
# and Unix build
# TODO(AD): Only enable ZLib for legacy _nassl?
ZLIB_PATH = join(getcwd(), 'zlib-1.2.11')

MODERN_OPENSSL_PATH = join(getcwd(), 'openssl-master')  # Tested with 1f5878b8e25a785dde330bf485e6ed5a6ae09a1a
LEGACY_OPENSSL_PATH = join(getcwd(), 'openssl-1.0.2e')


class OpenSslBuildConfig(object):

    __metaclass__ = ABCMeta

    def __init__(self, platform, openssl_src_path, zlib_lib_path, zlib_include_path, should_build_for_debug=False):
        self.platform = platform
        self.openssl_src_path = openssl_src_path
        self.zlib_lib_path = zlib_lib_path
        self.zlib_include_path = zlib_include_path

        if platform not in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64] \
                and should_build_for_debug:
            raise ValueError('Debug builds only supported for Windows')
        self.should_build_for_debug = should_build_for_debug

    @property
    def build_target(self):
        # type: () -> Text
        if self.platform == SupportedPlatformEnum.WINDOWS_32:
            if self.should_build_for_debug:
                openssl_target = 'debug-VC-WIN32'
            else:
                openssl_target = 'VC-WIN32'

        elif self.platform == SupportedPlatformEnum.WINDOWS_64:
            if self.should_build_for_debug:
                openssl_target = 'debug-VC-WIN64A'
            else:
                openssl_target = 'VC-WIN64A'

        elif self.platform == SupportedPlatformEnum.OSX_64:
            openssl_target = 'darwin64-x86_64-cc'

        elif self.platform == SupportedPlatformEnum.LINUX_64:
            openssl_target = 'linux-x86_64'

        elif self.platform == SupportedPlatformEnum.LINUX_32:
            openssl_target = 'linux-elf'

        elif self.platform == SupportedPlatformEnum.FREEBSD_64:
            openssl_target = 'BSD-x86_64'


        else:
            raise ValueError('Unknown platform')

        return openssl_target

    _OPENSSL_CONF_CMD = (
        'perl Configure {target} no-shared enable-rc5 enable-md2 enable-gost '
        'enable-cast enable-idea enable-ripemd enable-mdc2 '
        'enable-weak-ssl-ciphers enable-ssl2 {extra_args}'
    )


    @property
    def configure_command(self):
        # type: () -> Text
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            extra_args = '-no-asm -DZLIB_WINAPI'  # *hate* zlib
        else:
            extra_args = ' -fPIC'

        return self._OPENSSL_CONF_CMD.format(
            target=self.build_target,
            zlib_lib_path=self.zlib_lib_path,
            zlib_include_path=self.zlib_include_path,
            extra_args=extra_args
        )

    @property
    def build_steps(self):
        # type: () -> List[Text]
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            if self.platform == SupportedPlatformEnum.WINDOWS_32:
                do_build_step = 'ms\\do_ms'
            else:
                do_build_step = 'ms\\do_win64a.bat'

            return [
                self.configure_command,
                do_build_step,
                'nmake -f ms\\nt.mak clean',  # Does not work if tmp32 does not exist (openssl was never built)
                'nmake -f ms\\nt.mak',
            ]

        else:
            return [
                self.configure_command,
                'make clean',
                'make build_libs',  # Only build the libs as it is faster - not available on Windows
            ]

    @property
    def libcrypto_path(self):
        # type: () -> Text
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return join(self.openssl_src_path, 'out32', 'libeay32.lib')
        else:
            return join(self.openssl_src_path, 'libcrypto.a')

    @property
    def libssl_path(self):
        # type: () -> Text
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return join(self.openssl_src_path, 'out32', 'ssleay32.lib')
        else:
            return join(self.openssl_src_path, 'libssl.a')

    @property
    def include_path(self):
        # type: () -> Text
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return join(self.openssl_src_path, 'inc32', 'openssl')
        else:
            return join(self.openssl_src_path, 'include', 'openssl')


class LegacyOpenSslBuildConfig(OpenSslBuildConfig):
    """All configuration needed to build OpenSSL 1.0.2e.
    """
    pass


class ModernOpenSslBuildConfig(OpenSslBuildConfig):
    """All configuration needed to build OpenSSL 1.1.1-dev.
    """

    _OPENSSL_CONF_CMD = (
        'perl Configure {target} zlib no-zlib-dynamic no-shared enable-rc5 enable-md2 enable-gost '
        'enable-cast enable-idea enable-ripemd enable-mdc2 --with-zlib-include={zlib_include_path} '
        '--with-zlib-lib={zlib_lib_path} enable-weak-ssl-ciphers enable-tls1_3 {extra_args} no-async'
    )

    @property
    def build_steps(self):
        # type: () -> List[Text]
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return [
                self.configure_command,
                'nmake clean',
                'nmake build_libs',
            ]
        else:
            return super(ModernOpenSslBuildConfig, self).build_steps

    @property
    def libcrypto_path(self):
        # type: () -> Text
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return join(self.openssl_src_path, 'libcrypto.lib')
        else:
            return super(ModernOpenSslBuildConfig, self).libcrypto_path

    @property
    def libssl_path(self):
        # type: () -> Text
        if self.platform in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
            return join(self.openssl_src_path, 'libssl.lib')
        else:
            return super(ModernOpenSslBuildConfig, self).libssl_path

    @property
    def include_path(self):
        # type: () -> Text
        return join(self.openssl_src_path, 'include', 'openssl')


def perform_build_task(title, commands_dict, cwd=None):
    print ('===BUILDING {0}==='.format(title))
    for command in commands_dict:
        subprocess.check_call(command, shell=True, cwd=cwd)


def copy_openssl_build_result(openssl_config, nassl_include_path_out, nassl_libraries_path_out):
    # Reset the include folder
    if os.path.exists(nassl_include_path_out):
        shutil.rmtree(nassl_include_path_out)

    # Move the static libraries and include to the right folder
    shutil.copytree(openssl_config.include_path, join(nassl_include_path_out, 'openssl'))
    shutil.copy(openssl_config.libcrypto_path, nassl_libraries_path_out)
    shutil.copy(openssl_config.libssl_path, nassl_libraries_path_out)


def build_legacy_openssl():
    openssl_config = LegacyOpenSslBuildConfig(CURRENT_PLATFORM, LEGACY_OPENSSL_PATH, ZLIB_LIB_INSTALL_PATH, ZLIB_PATH,
                                              SHOULD_BUILD_FOR_DEBUG)
    perform_build_task('LEGACY OPENSSL', openssl_config.build_steps, LEGACY_OPENSSL_PATH)
    copy_openssl_build_result(openssl_config, LEGACY_OPENSSL_HEADERS_INSTALL_PATH, LEGACY_OPENSSL_LIB_INSTALL_PATH)

    # Copy some internal headers for accessing EDH and ECDH parameters
    internal_headers_install_path = join(LEGACY_OPENSSL_HEADERS_INSTALL_PATH, 'openssl-internal')
    if not os.path.isdir(internal_headers_install_path):
        os.makedirs(internal_headers_install_path)
    shutil.copy(join(LEGACY_OPENSSL_PATH, 'e_os.h'), internal_headers_install_path)
    shutil.copy(join(LEGACY_OPENSSL_PATH, 'ssl', 'ssl_locl.h'), internal_headers_install_path)


def build_modern_openssl():
    openssl_config = ModernOpenSslBuildConfig(CURRENT_PLATFORM, MODERN_OPENSSL_PATH, ZLIB_LIB_INSTALL_PATH, ZLIB_PATH,
                                              SHOULD_BUILD_FOR_DEBUG)
    perform_build_task('MODERN OPENSSL', openssl_config.build_steps, MODERN_OPENSSL_PATH)
    copy_openssl_build_result(openssl_config, MODERN_OPENSSL_HEADERS_INSTALL_PATH, MODERN_OPENSSL_LIB_INSTALL_PATH)


def build_zlib():
    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
        ZLIB_LIB_PATH = ZLIB_PATH + '\\contrib\\vstudio\\vc14\\x86\\ZlibStatRelease\\zlibstat.lib'
        ZLIB_BUILD_TASKS = [
            'bld_ml32.bat',
            'msbuild ..\\vstudio\\vc14\\zlibvc.sln /P:Configuration=Release /P:Platform=Win32"'
        ]
        perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_PATH + '\\contrib\\masmx86\\')

    elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
        ZLIB_LIB_PATH = ZLIB_PATH + '\\contrib\\vstudio\\vc14\\x64\\ZlibStatRelease\\zlibstat.lib'
        ZLIB_BUILD_TASKS = [
            'bld_ml64.bat',
            'msbuild ..\\vstudio\\vc14\\zlibvc.sln /P:Configuration=Release /P:Platform=x64"'
        ]
        perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_PATH + '\\contrib\\masmx64\\')

    else:
        ZLIB_LIB_PATH = join(ZLIB_PATH, 'libz.a')
        ZLIB_BUILD_TASKS = [
            'CFLAGS="-fPIC" ./configure -static',
            'make clean',
            'make'
        ]
        perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_PATH)

    # Keep the Zlib around as it is linked into OpenSSL
    if not os.path.isdir(os.path.dirname(ZLIB_LIB_INSTALL_PATH)):
        os.makedirs(os.path.dirname(ZLIB_LIB_INSTALL_PATH))
    shutil.copy(ZLIB_LIB_PATH, ZLIB_LIB_INSTALL_PATH)


def main():
    # Build all the libraries needed
#    build_zlib()
    build_legacy_openssl()
#    build_modern_openssl()

#    # Build nassl
#    NASSL_EXTRA_ARGS = ''
#    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
#        NASSL_EXTRA_ARGS = ' --plat-name=win32'
#    elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
#        NASSL_EXTRA_ARGS = ' --plat-name=win-amd64'
#
#    # Reset the ./build folder if there was a previous version of nassl
#    build_path = os.path.join(os.path.dirname(__file__), 'build')
#    if os.path.exists(build_path):
#        shutil.rmtree(build_path)
#    NASSL_BUILD_TASKS = [
#        '{python} setup.py build_ext -i{extra_args}'.format(python=sys.executable, extra_args=NASSL_EXTRA_ARGS)
#    ]
#    perform_build_task('NASSL', NASSL_BUILD_TASKS)
#
#    # Test nassl
#    NASSL_TEST_TASKS = ['{python} setup.py test'.format(python=sys.executable)]
#    #perform_build_task('NASSL Tests', NASSL_TEST_TASKS)

    print ('=== All Done! ===')


if __name__ == "__main__":
    main()
