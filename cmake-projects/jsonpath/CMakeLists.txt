cmake_minimum_required(VERSION 2.6)

PROJECT(jsonpath C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-error=unused-variable -ffunction-sections -D_GNU_SOURCE)

IF(NOT APPLE)
  SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "-Wl,--gc-sections")
ENDIF()

find_library(json NAMES json-c json)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(JSONC json-c json)
IF(JSONC_FOUND)
  ADD_DEFINITIONS(-DJSONC)
  INCLUDE_DIRECTORIES(${JSONC_INCLUDE_DIRS})
ENDIF()

ADD_CUSTOM_COMMAND(
  OUTPUT lemon
  DEPENDS ${CMAKE_SOURCE_DIR}/contrib/lemon.c ${CMAKE_SOURCE_DIR}/contrib/lempar.c
  COMMAND gcc -o lemon -I "${CMAKE_SOURCE_DIR}" "${CMAKE_SOURCE_DIR}/contrib/lemon.c"
  COMMENT "Generating lemon parser generator"
)

ADD_CUSTOM_COMMAND(
  OUTPUT ${CMAKE_SOURCE_DIR}/parser.c
  DEPENDS ${CMAKE_SOURCE_DIR}/parser.y lemon
  COMMAND cd "${CMAKE_SOURCE_DIR}" && ${CMAKE_BINARY_DIR}/lemon -T${CMAKE_SOURCE_DIR}/contrib/lempar.c parser.y
  COMMENT "Generating parser.c"
)

FIND_PATH(ubox_include_dir libubox/list.h)
IF(ubox_include_dir MATCHES "NOTFOUND$")
  ADD_SUBDIRECTORY(libubox)
  INCLUDE_DIRECTORIES(libubox)
ELSE()
  INCLUDE_DIRECTORIES(${ubox_include_dir})
ENDIF()

SET_PROPERTY(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "lemon;parser.h;parser.out")
SET_SOURCE_FILES_PROPERTIES("parser.c" PROPERTIES GENERATED TRUE)

SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
SET(BUILD_SHARED_LIBS OFF)
SET(CMAKE_EXE_LINKER_FLAGS "-static")

ADD_EXECUTABLE(jsonpath main.c ast.c lexer.c parser.c matcher.c)
TARGET_LINK_LIBRARIES(jsonpath ubox-static ${json})

INSTALL(TARGETS jsonpath RUNTIME DESTINATION bin)
