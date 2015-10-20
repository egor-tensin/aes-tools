find_package(Boost REQUIRED COMPONENTS program_options)

add_executable(util_encrypt_block encrypt_block.cpp block_cmd_parser.hpp block_dumper.hpp data_parsers.hpp)
target_include_directories(util_encrypt_block PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_encrypt_block libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_encrypt_block PROPERTIES OUTPUT_NAME encrypt_block)

add_executable(util_decrypt_block decrypt_block.cpp block_cmd_parser.hpp block_dumper.hpp data_parsers.hpp)
target_include_directories(util_decrypt_block PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_decrypt_block libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_decrypt_block PROPERTIES OUTPUT_NAME decrypt_block)

add_executable(util_encrypt_file encrypt_file.cpp file_cmd_parser.hpp data_parsers.hpp)
target_include_directories(util_encrypt_file PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_encrypt_file libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_encrypt_file PROPERTIES OUTPUT_NAME encrypt_file)

add_executable(util_decrypt_file decrypt_file.cpp file_cmd_parser.hpp data_parsers.hpp)
target_include_directories(util_decrypt_file PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_decrypt_file libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_decrypt_file PROPERTIES OUTPUT_NAME decrypt_file)

add_executable(util_encrypt_bmp encrypt_bmp.cpp file_cmd_parser.hpp data_parsers.hpp)
target_include_directories(util_encrypt_bmp PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_encrypt_bmp libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_encrypt_bmp PROPERTIES OUTPUT_NAME encrypt_bmp)

add_executable(util_decrypt_bmp decrypt_bmp.cpp file_cmd_parser.hpp data_parsers.hpp)
target_include_directories(util_decrypt_bmp PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_decrypt_bmp libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_decrypt_bmp PROPERTIES OUTPUT_NAME decrypt_bmp)
