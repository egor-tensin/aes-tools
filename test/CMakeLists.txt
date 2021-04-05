find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME nist       COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/nist.py" --path "$<TARGET_FILE_DIR:util_encrypt_block>") 
add_test(NAME nist_boxes COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/nist.py" --path "$<TARGET_FILE_DIR:util_encrypt_block>" --boxes)
add_test(NAME cavp       COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/cavp.py" --path "$<TARGET_FILE_DIR:util_encrypt_block>") 
add_test(NAME cavp_boxes COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/cavp.py" --path "$<TARGET_FILE_DIR:util_encrypt_block>" --boxes)
add_test(NAME file       COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/file.py" --path "$<TARGET_FILE_DIR:util_encrypt_file>")

set_tests_properties(nist PROPERTIES
                     FAIL_REGULAR_EXPRESSION "Failed: *[1-9]"
                     PASS_REGULAR_EXPRESSION "Succeeded: *30")
set_tests_properties(nist_boxes PROPERTIES
                     FAIL_REGULAR_EXPRESSION "Failed: *[1-9]"
                     PASS_REGULAR_EXPRESSION "Succeeded: *30")
set_tests_properties(cavp PROPERTIES
                     FAIL_REGULAR_EXPRESSION "Failed: *[1-9]"
                     PASS_REGULAR_EXPRESSION "Succeeded: *96")
set_tests_properties(cavp_boxes PROPERTIES
                     FAIL_REGULAR_EXPRESSION "Failed: *[1-9]"
                     PASS_REGULAR_EXPRESSION "Succeeded: *96")
set_tests_properties(file PROPERTIES
                     FAIL_REGULAR_EXPRESSION "Failed: *[1-9]"
                     PASS_REGULAR_EXPRESSION "Succeeded: *180")
