cmake_minimum_required(VERSION 3.10)
project(FileServer)

# Set C source files
set(SOURCE_FILES src/main.c)

# Create executable
add_executable(share ${SOURCE_FILES})

# Set output directory
set_target_properties(share PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
