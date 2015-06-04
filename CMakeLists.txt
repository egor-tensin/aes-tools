project(libaesni C ASM_MASM)
file(GLOB_RECURSE ${PROJECT_NAME}_headers "include/*.h")
file(GLOB ${PROJECT_NAME}_sources "src/*.c")
add_library(${PROJECT_NAME} ${${PROJECT_NAME}_headers}
                            ${${PROJECT_NAME}_sources})
target_include_directories(${PROJECT_NAME} PUBLIC include/)
target_compile_definitions(${PROJECT_NAME} PRIVATE _CRT_SECURE_NO_WARNINGS)

add_subdirectory(examples)
add_subdirectory(test)
