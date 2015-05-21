project(libaesni C ASM_MASM)
file(GLOB_RECURSE ${PROJECT_NAME}_headers "include/*.h")
file(GLOB ${PROJECT_NAME}_sources "src/*.asm" "src/*.c")
add_library(${PROJECT_NAME} ${${PROJECT_NAME}_headers}
                            ${${PROJECT_NAME}_sources})
target_include_directories(${PROJECT_NAME} PUBLIC include/)

add_subdirectory(examples)
