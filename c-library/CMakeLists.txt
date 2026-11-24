cmake_minimum_required(VERSION 3.20)
project(callanalyzer VERSION 1.0.0 LANGUAGES C)

option(CA_ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(CA_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(CA_BUILD_TESTS "Build the test executables" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(CA_WARNING_FLAGS
  -Wall -Wextra -Wpedantic
  -Wshadow -Wconversion -Wsign-conversion -Wdouble-promotion
  -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition
  -Wcast-qual -Wnull-dereference -Wvla -Wundef -Wswitch-enum)
if(CA_WARNINGS_AS_ERRORS)
  list(APPEND CA_WARNING_FLAGS -Werror)
endif()

set(CA_SANITIZER_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)

set(CA_SOURCES
  src/parser.c
  src/analyzer.c
  src/statistics.c
  src/anomaly.c
  src/utils.c)

function(ca_configure_target target)
  target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
                                      PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_options(${target} PRIVATE ${CA_WARNING_FLAGS})
  target_link_libraries(${target} PUBLIC m)
  if(CA_ENABLE_SANITIZERS)
    target_compile_options(${target} PRIVATE ${CA_SANITIZER_FLAGS})
    target_link_options(${target} PUBLIC ${CA_SANITIZER_FLAGS})
  endif()
endfunction()

# Production shared library: only the public API is exported.
add_library(callanalyzer SHARED ${CA_SOURCES})
ca_configure_target(callanalyzer)
target_compile_definitions(callanalyzer PRIVATE CA_BUILDING_SHARED)
set_target_properties(callanalyzer PROPERTIES
  C_VISIBILITY_PRESET hidden
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR})

include(GNUInstallDirs)
install(TARGETS callanalyzer LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/call_analyzer.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(CA_BUILD_TESTS)
  enable_testing()

  # Same tests against the shared library as shipped.
  add_executable(test_call_analyzer tests/test_call_analyzer.c)
  target_compile_options(test_call_analyzer PRIVATE ${CA_WARNING_FLAGS})
  target_compile_definitions(test_call_analyzer PRIVATE
    CA_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
  target_link_libraries(test_call_analyzer PRIVATE callanalyzer)
  add_test(NAME call_analyzer COMMAND test_call_analyzer)

  # Static build with allocation-failure injection for out-of-memory tests.
  add_library(callanalyzer_fault STATIC ${CA_SOURCES})
  ca_configure_target(callanalyzer_fault)
  target_compile_definitions(callanalyzer_fault PUBLIC CA_FAULT_INJECTION)
  add_executable(test_call_analyzer_fault tests/test_call_analyzer.c)
  target_compile_options(test_call_analyzer_fault PRIVATE ${CA_WARNING_FLAGS})
  target_compile_definitions(test_call_analyzer_fault PRIVATE
    CA_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
  target_link_libraries(test_call_analyzer_fault PRIVATE callanalyzer_fault)
  add_test(NAME call_analyzer_fault_injection COMMAND test_call_analyzer_fault)
endif()
