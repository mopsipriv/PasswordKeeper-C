cmake_minimum_required(VERSION 3.16)

project(passwordkeep LANGUAGES C)

add_executable(passwordkeep main.c
    sha256.c
    encryptor.c)

include(GNUInstallDirs)
install(TARGETS passwordkeep
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
