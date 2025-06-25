cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME pdf_scanner)

# DuckDB's extension distribution supports vcpkg. As such, dependencies can be added in ./vcpkg.json and then
# used in cmake with find_package. Feel free to remove or replace with other dependencies.
# Note that it should also be removed from vcpkg.json to prevent needlessly installing it..
find_package(OpenSSL REQUIRED)
find_package(LibArchive REQUIRED)
find_package(TIFF REQUIRED)
find_package(TIFF REQUIRED)
find_package(WebP CONFIG REQUIRED)
find_package(GIF REQUIRED)
find_package(CURL REQUIRED)
find_package(BZip2 REQUIRED)
find_package(unofficial-brotli CONFIG REQUIRED)
find_package(lz4 REQUIRED)
find_package(liblzma CONFIG REQUIRED)
find_package(zstd REQUIRED)

find_path(MUPDF_INCLUDE_DIR mupdf/fitz.h PATHS "${CMAKE_PREFIX_PATH}/include")
find_library(MUPDF_LIBRARY NAMES libmupdf PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(OPENJP2_LIBRARY NAMES openjp2 PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(TESSERACT_LIBRARY NAMES tesseract PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(LEPTONICA_LIBRARY NAMES leptonica PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(FREETYPE_LIBRARY NAMES freetype PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(JPEG_LIBRARY NAMES jpeg PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(PNG_LIBRARY NAMES png PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(ZLIB_LIBRARY NAMES z PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(JBIG2DEC_LIBRARY NAMES jbig2dec PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(HARFBUZZ_LIBRARY NAMES harfbuzz PATHS "${CMAKE_PREFIX_PATH}/lib")
find_library(GUMBO_LIBRARY NAMES gumbo PATHS "${CMAKE_PREFIX_PATH}/lib")

if(NOT MUPDF_INCLUDE_DIR OR NOT MUPDF_LIBRARY)
  message(FATAL_ERROR "MuPDF not found. Make sure it is installed with vcpkg and CMAKE_PREFIX_PATH is set correctly.")
endif()

add_library(libmupdf::libmupdf UNKNOWN IMPORTED)
set_target_properties(libmupdf::libmupdf PROPERTIES
    IMPORTED_LOCATION "${MUPDF_LIBRARY}"
    #INTERFACE_INCLUDE_DIRECTORIES "${MUPDF_INCLUDE_DIR}"
)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

set(EXTENSION_SOURCES src/pdf_scanner_extension.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# Link OpenSSL in both the static library as the loadable extension
target_link_libraries(${EXTENSION_NAME}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${MUPDF_LIBRARY}
    ${OPENJP2_LIBRARY}
    ${TESSERACT_LIBRARY}
    ${LEPTONICA_LIBRARY}
    ${FREETYPE_LIBRARY}
    ${JPEG_LIBRARY}
    ${PNG_LIBRARY}
    ${ZLIB_LIBRARY}
    ${JBIG2DEC_LIBRARY}
    ${HARFBUZZ_LIBRARY}
    ${GUMBO_LIBRARY}
    LibArchive::LibArchive
    CURL::libcurl
    TIFF::TIFF
    WebP::webp WebP::webpdecoder WebP::webpdemux
    GIF::GIF
    BZip2::BZip2
    unofficial::brotli::brotlidec
    unofficial::brotli::brotlienc
    brotlicommon
    pthread
    dl
    lz4::lz4
    liblzma::liblzma
    zstd::libzstd
)

target_link_libraries(${LOADABLE_EXTENSION_NAME}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${MUPDF_LIBRARY}
    ${OPENJP2_LIBRARY}
    ${TESSERACT_LIBRARY}
    ${LEPTONICA_LIBRARY}
    ${FREETYPE_LIBRARY}
    ${JPEG_LIBRARY}
    ${PNG_LIBRARY}
    ${ZLIB_LIBRARY}
    ${JBIG2DEC_LIBRARY}
    ${HARFBUZZ_LIBRARY}
    ${GUMBO_LIBRARY}
    LibArchive::LibArchive
    CURL::libcurl
    TIFF::TIFF
    WebP::webp WebP::webpdecoder WebP::webpdemux
    GIF::GIF
    BZip2::BZip2
    unofficial::brotli::brotlidec
    unofficial::brotli::brotlienc
    brotlicommon
    pthread
    dl
    lz4::lz4
    liblzma::liblzma
    zstd::libzstd
)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
