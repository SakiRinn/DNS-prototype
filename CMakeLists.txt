cmake_minimum_required(VERSION 3.0.0)
project(SimpleDNS)
include(CTest)
enable_testing()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

link_libraries(m)

add_subdirectory(include)
include_directories(include)

add_subdirectory(src)
aux_source_directory(src SRC_DIR)

add_executable(client client.c ${SRC_DIR})
add_executable(local_server server/local_server.c ${SRC_DIR})
add_executable(comorg server/comorg.c ${SRC_DIR})
add_executable(edu server/edu.c ${SRC_DIR})
add_executable(gov server/gov.c ${SRC_DIR})
add_executable(ptr server/ptr.c ${SRC_DIR})
add_executable(cnus server/cnus.c ${SRC_DIR})
add_executable(root server/root.c ${SRC_DIR})