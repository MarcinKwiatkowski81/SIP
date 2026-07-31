# Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
# All rights reserved.


cmake_minimum_required(VERSION 3.16)
project(sip_stack CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SIP_BUILD_TESTS "Build unit tests" OFF)
option(SIP_ASAN "Enable AddressSanitizer" OFF)
option(SIP_BUILD_DOCS "Build API docs with Doxygen" OFF)

find_package(Threads REQUIRED)

# ── Optional codec library detection ─────────────────────────────────────────
# find versioned .so files directly
find_file(LIB_GSM    NAMES libgsm.so.1    libgsm.so    HINTS /usr/lib/x86_64-linux-gnu NO_DEFAULT_PATH)
find_file(LIB_BCG729 NAMES libbcg729.so.0 libbcg729.so HINTS /usr/lib/x86_64-linux-gnu NO_DEFAULT_PATH)
find_file(LIB_CODEC2 NAMES libcodec2.so.1.2 libcodec2.so HINTS /usr/lib/x86_64-linux-gnu NO_DEFAULT_PATH)
find_library(LIB_DL dl)

set(CODEC_DEFINES "")
set(CODEC_LIBS    "")
if(LIB_GSM)
    list(APPEND CODEC_DEFINES HAVE_GSM)
    list(APPEND CODEC_LIBS    ${LIB_GSM})
    message(STATUS "Codec: GSM-FR    ${LIB_GSM}")
endif()
if(LIB_BCG729)
    list(APPEND CODEC_DEFINES HAVE_BCG729)
    list(APPEND CODEC_LIBS    ${LIB_BCG729})
    message(STATUS "Codec: G.729A    ${LIB_BCG729}")
endif()
if(LIB_CODEC2)
    list(APPEND CODEC_DEFINES HAVE_CODEC2)
    list(APPEND CODEC_LIBS    ${LIB_CODEC2})
    message(STATUS "Codec: CODEC2    ${LIB_CODEC2}")
endif()

# ── Core library ──────────────────────────────────────────────────────────────
set(CORE_SOURCES
    src/Codec.cpp
    src/CodecPlugin.cpp
    src/Uri.cpp
    src/SipMessage.cpp
    src/Transaction.cpp
    src/Dialog.cpp
    src/Sdp.cpp
    src/Rtp.cpp
    src/Transport.cpp
    src/SipStack.cpp
    src/UserDb.cpp
    src/RegistrarDb.cpp
    src/Cdr.cpp
    src/SipServer.cpp
)

add_library(sip_core STATIC ${CORE_SOURCES})
target_include_directories(sip_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(sip_core PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)
target_compile_definitions(sip_core PUBLIC ${CODEC_DEFINES})
target_link_libraries(sip_core PUBLIC Threads::Threads ${CODEC_LIBS})
if(LIB_DL)
    target_link_libraries(sip_core PUBLIC ${LIB_DL})
endif()

# ── sip_client (interactive UA) ───────────────────────────────────────────────
add_executable(sip_client src/main.cpp)
target_link_libraries(sip_client PRIVATE sip_core)
target_compile_options(sip_client PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

# ── sip_server ────────────────────────────────────────────────────────────────
add_executable(sip_server src/sip_server_main.cpp)
target_link_libraries(sip_server PRIVATE sip_core)
target_compile_options(sip_server PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)

# ── call_and_record sample ────────────────────────────────────────────────────
add_executable(call_and_record samples/call_and_record.cpp)
target_include_directories(call_and_record PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/samples
)
target_link_libraries(call_and_record PRIVATE sip_core)
target_compile_options(call_and_record PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)

# ── receive_and_record sample ───────────────────────────────────────────────
add_executable(receive_and_record samples/receive_and_record.cpp)
target_include_directories(receive_and_record PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/samples
)
target_link_libraries(receive_and_record PRIVATE sip_core)
target_compile_options(receive_and_record PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)

# ── sample_pbx (registrar + B2BUA PBX) ───────────────────────────────────────
add_executable(sample_pbx
    samples/pbx/main.cpp
    samples/pbx/PbxApp.cpp
)
target_include_directories(sample_pbx PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/pbx
)
target_link_libraries(sample_pbx PRIVATE sip_core)
target_compile_options(sample_pbx PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)

add_executable(transcode_smoke samples/pbx/transcode_smoke.cpp)
target_include_directories(transcode_smoke PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/pbx
)
target_link_libraries(transcode_smoke PRIVATE sip_core)
target_compile_options(transcode_smoke PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)

if(SIP_ASAN)
    foreach(TGT sip_core sip_client sip_server call_and_record receive_and_record sample_pbx transcode_smoke)
        target_compile_options(${TGT} PRIVATE -fsanitize=address,undefined)
        target_link_options(${TGT}    PRIVATE -fsanitize=address,undefined)
    endforeach()
endif()

install(TARGETS sip_client sip_server RUNTIME DESTINATION bin)
install(TARGETS sip_core              ARCHIVE DESTINATION lib)
install(DIRECTORY include/            DESTINATION include/sip)

if(SIP_BUILD_TESTS)
    enable_testing()
endif()

if(SIP_BUILD_DOCS)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/docs)
        set(DOXYGEN_INPUT_LIST
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/samples
            ${CMAKE_CURRENT_SOURCE_DIR}/README.md
            ${CMAKE_CURRENT_SOURCE_DIR}/docs/mainpage.md)
        string(REPLACE ";" " " DOXYGEN_INPUT_DIR "${DOXYGEN_INPUT_LIST}")
        set(DOXYGEN_EXCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/tmp)
        set(DOXYGEN_MAINPAGE ${CMAKE_CURRENT_SOURCE_DIR}/docs/mainpage.md)
        set(DOXYGEN_STRIP_PATH ${CMAKE_CURRENT_SOURCE_DIR})
        set(DOXYGEN_HAVE_DOT NO)
        if(DOXYGEN_DOT_FOUND)
            set(DOXYGEN_HAVE_DOT YES)
        endif()

        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
                       ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

        add_custom_target(docs
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM)
    else()
        message(WARNING "SIP_BUILD_DOCS=ON but Doxygen was not found. Install doxygen to enable docs target.")
    endif()
endif()

message(STATUS "sip_stack | C++${CMAKE_CXX_STANDARD} | ${CMAKE_BUILD_TYPE} | asan=${SIP_ASAN}")
message(STATUS "Codecs: ${CODEC_DEFINES}")
