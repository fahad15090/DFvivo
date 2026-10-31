cmake_minimum_required(VERSION 3.22)
project(dfprobe C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -fno-stack-protector -fomit-frame-pointer")

# Runnable binary packaged as libdfprobe.so so AGP places it in nativeLibraryDir,
# which is the only exec-allowed location for an app (same trick as DFRoot).
add_executable(dfprobe probe.c)
target_link_libraries(dfprobe z)
set_target_properties(dfprobe PROPERTIES
    PREFIX "lib"
    SUFFIX ".so"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
