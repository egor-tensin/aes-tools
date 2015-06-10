project(libaesni C CXX ASM_MASM)
file(GLOB_RECURSE ${PROJECT_NAME}_headers "include/*.h")
if(AESNI_USE_ASM)
    file(GLOB ${PROJECT_NAME}_c_sources "src/*.c")
    file(GLOB ${PROJECT_NAME}_asm_sources "src/asm/*.asm")
    set(${PROJECT_NAME}_sources ${${PROJECT_NAME}_asm_sources} ${${PROJECT_NAME}_c_sources})
    set_source_files_properties(${${PROJECT_NAME}_asm_sources} PROPERTIES COMPILE_FLAGS "/safeseh")
    # Setting CMAKE_ASM_MASM_FLAGS doesn't work: http://www.cmake.org/Bug/view.php?id=14711
else()
    file(GLOB_RECURSE ${PROJECT_NAME}_sources "src/*.c")
endif()
add_library(${PROJECT_NAME} ${${PROJECT_NAME}_headers}
                            ${${PROJECT_NAME}_sources})
target_include_directories(${PROJECT_NAME} PUBLIC include/)
target_compile_definitions(${PROJECT_NAME} PRIVATE _CRT_SECURE_NO_WARNINGS)

add_subdirectory(examples)
add_subdirectory(test)
add_subdirectory(utils)
