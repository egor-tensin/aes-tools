find_package(Boost REQUIRED COMPONENTS filesystem program_options)

function(add_util name src)
    set(target "util_${name}")
    add_executable("${target}" ${src})
    target_link_libraries("${target}" PRIVATE aesxx Boost::disable_autolinking Boost::filesystem Boost::program_options)
    set_target_properties("${target}" PROPERTIES OUTPUT_NAME "${name}")
    install(TARGETS "${target}" RUNTIME DESTINATION bin)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        install(FILES "$<TARGET_PDB_FILE:${target}>" DESTINATION bin OPTIONAL)
    endif()
endfunction()

set(block_util_headers block_cmd_parser.hpp block_dumper.hpp block_input.hpp data_parsers.hpp helpers/command_line.hpp)

add_util(encrypt_block encrypt_block.cpp ${block_util_headers})
add_util(decrypt_block decrypt_block.cpp ${block_util_headers})

set(file_util_headers data_parsers.hpp file_cmd_parser.hpp helpers/command_line.hpp helpers/file.hpp)

add_util(encrypt_file encrypt_file.cpp ${file_util_headers})
add_util(decrypt_file decrypt_file.cpp ${file_util_headers})

set(bmp_util_headers ${file_util_headers} helpers/bmp.hpp)

add_util(encrypt_bmp encrypt_bmp.cpp ${bmp_util_headers})
add_util(decrypt_bmp decrypt_bmp.cpp ${bmp_util_headers})
