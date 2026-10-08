cmake_minimum_required(VERSION 3.16)
project(harness_nego C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT DEFINED FREERDP_SRC)
  message(FATAL_ERROR "butuh -DFREERDP_SRC=<direktori sumber FreeRDP>")
endif()
# winpr/config.h itu header HASIL GENERATE → hanya ada di direktori build & prefix install
if(NOT DEFINED FREERDP_BUILD)
  set(FREERDP_BUILD "${CMAKE_CURRENT_BINARY_DIR}/../build-freerdp")
endif()
if(NOT DEFINED FREERDP_INSTALL)
  set(FREERDP_INSTALL "$ENV{HOME}/frdp")
endif()

find_package(FreeRDP REQUIRED)

add_executable(harness_nego harness_nego.c)

# header internal FreeRDP (nego.h dll) ada di pohon sumber, bukan selalu di prefix install
target_include_directories(harness_nego PRIVATE
  "${FREERDP_INSTALL}/include"
  "${FREERDP_BUILD}/winpr/include"
  "${FREERDP_BUILD}/include"
  "${FREERDP_SRC}/include"
  "${FREERDP_SRC}/libfreerdp"
  "${FREERDP_SRC}/winpr/include")

# nama target ekspor berbeda antar rilis FreeRDP → Client opsional (harness hanya butuh core/nego)
set(FRDP_LIBS "")
if(TARGET FreeRDP::Client)
  list(APPEND FRDP_LIBS FreeRDP::Client)
elseif(TARGET freerdp-client3)
  list(APPEND FRDP_LIBS freerdp-client3)
elseif(TARGET freerdp-client2)
  list(APPEND FRDP_LIBS freerdp-client2)
endif()
if(TARGET FreeRDP::Common)
  list(APPEND FRDP_LIBS FreeRDP::Common)
elseif(TARGET freerdp3)
  list(APPEND FRDP_LIBS freerdp3)
else()
  list(APPEND FRDP_LIBS freerdp2)
endif()
if(TARGET FreeRDP::WinPR)
  list(APPEND FRDP_LIBS FreeRDP::WinPR)
elseif(TARGET winpr3)
  list(APPEND FRDP_LIBS winpr3)
else()
  list(APPEND FRDP_LIBS winpr2)
endif()

target_link_libraries(harness_nego PRIVATE ${FRDP_LIBS})

# sanitizer ikut ke binary harness
target_compile_options(harness_nego PRIVATE -fsanitize=address -fno-omit-frame-pointer -g -O1)
target_link_options(harness_nego PRIVATE -fsanitize=address)
