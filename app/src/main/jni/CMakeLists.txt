cmake_minimum_required(VERSION 3.22)
project(dfprobe C)
enable_language(ASM)

set(JNI_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -I${JNI_DIR}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${JNI_DIR} -O2 -Wall -Wno-unused-function -fno-stack-protector -fomit-frame-pointer")

# Runnable binary packaged as libdfprobe.so so AGP places it in nativeLibraryDir,
# which is the only exec-allowed location for an app (same trick as DFRoot).
# probe.c = stage-1 write primitive; hook.c = stage-2 libc++ hook;
# libcxx.S = stage-2 blob (written by the hook into libc++.so's page slack).
add_executable(dfprobe probe.c hook.c libcxx.S)
target_link_libraries(dfprobe z)
set_target_properties(dfprobe PROPERTIES
    PREFIX "lib"
    SUFFIX ".so"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
