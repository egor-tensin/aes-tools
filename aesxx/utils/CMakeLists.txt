find_package(Boost CONFIG REQUIRED COMPONENTS program_options)

function(add_util name src)
    set(target "util_${name}")
    add_executable("${target}" ${src})
    target_link_libraries("${target}" PRIVATE
        aesxx
        Boost::disable_autolinking
        Boost::program_options
    )
    set_target_properties("${target}" PROPERTIES OUTPUT_NAME "${name}")
    install(TARGETS "${target}" RUNTIME DESTINATION bin)
    if(MSVC)
        install(FILES "$<TARGET_PDB_FILE:${target}>" DESTINATION bin OPTIONAL)
    endif()
endfunction()

set(block_util_headers
    helpers/block_dumper.hpp
    helpers/cmd_parser.hpp
    helpers/cmd_paresr_block.hpp
    helpers/data_parsers.hpp
)

add_util(encrypt_block encrypt_block.cpp ${block_util_headers})
add_util(decrypt_block decrypt_block.cpp ${block_util_headers})

set(file_util_headers
    helpers/cmd_parser.hpp
    helpers/cmd_parser_file.hpp
    helpers/data_parsers.hpp
    helpers/file.hpp
)

add_util(encrypt_file encrypt_file.cpp ${file_util_headers})
add_util(decrypt_file decrypt_file.cpp ${file_util_headers})

set(bmp_util_headers ${file_util_headers} helpers/bmp.hpp)

add_util(encrypt_bmp encrypt_bmp.cpp ${bmp_util_headers})
add_util(decrypt_bmp decrypt_bmp.cpp ${bmp_util_headers})

find_package(Python3 REQUIRED COMPONENTS Interpreter)

include(test/basic.cmake)
include(test/block.cmake)
