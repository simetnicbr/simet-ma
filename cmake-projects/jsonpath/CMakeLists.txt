cmake_minimum_required(VERSION 3.10)

PROJECT(jsonpath C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-error=unused-variable -ffunction-sections -D_GNU_SOURCE)

IF(NOT APPLE)
  SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "-Wl,--gc-sections")
ENDIF()

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(JSONC json-c)
IF(JSONC_FOUND)
  ADD_DEFINITIONS(-DJSONC)
  INCLUDE_DIRECTORIES(${JSONC_INCLUDE_DIRS})
ENDIF()

ADD_CUSTOM_COMMAND(
  OUTPUT contrib/lemon
  DEPENDS contrib/lemon.c contrib/lempar.c
  COMMAND gcc -std=gnu17 -o contrib/lemon contrib/lemon.c
  COMMENT "Generating lemon parser generator"
)

ADD_CUSTOM_COMMAND(
  OUTPUT parser.c
  DEPENDS parser.y contrib/lemon
  COMMAND ./contrib/lemon parser.y
  COMMENT "Generating parser.c"
)

FIND_PATH(ubox_include_dir libubox/list.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})

SET_PROPERTY(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "lemon;parser.h;parser.out")
SET_SOURCE_FILES_PROPERTIES("parser.c" PROPERTIES GENERATED TRUE)
ADD_EXECUTABLE(jsonpath main.c ast.c lexer.c parser.c matcher.c)
find_library(json NAMES json-c)
TARGET_LINK_LIBRARIES(jsonpath ubox ${json})

INSTALL(TARGETS jsonpath RUNTIME DESTINATION bin)
