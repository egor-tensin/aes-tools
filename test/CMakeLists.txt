find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_test(NAME nist COMMAND Python3::Interpreter
    "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/tools/ctest-driver.py"
    run
    --pass-regex [=[Succeeded: *30$]=]
    --fail-regex [=[Failed: *[1-9]]=]
    --
    "$<TARGET_FILE:Python3::Interpreter>"
    "${CMAKE_CURRENT_SOURCE_DIR}/nist.py"
    --path "$<TARGET_FILE_DIR:util_encrypt_block>")
add_test(NAME nist_boxes COMMAND Python3::Interpreter
    "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/tools/ctest-driver.py"
    run
    --pass-regex [=[Succeeded: *30$]=]
    --fail-regex [=[Failed: *[1-9]]=]
    --
    "$<TARGET_FILE:Python3::Interpreter>"
    "${CMAKE_CURRENT_SOURCE_DIR}/nist.py"
    --path "$<TARGET_FILE_DIR:util_encrypt_block>"
    --boxes)
add_test(NAME cavp COMMAND Python3::Interpreter
    "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/tools/ctest-driver.py"
    run
    --pass-regex [=[Succeeded: *96$]=]
    --fail-regex [=[Failed: *[1-9]]=]
    --
    "$<TARGET_FILE:Python3::Interpreter>"
    "${CMAKE_CURRENT_SOURCE_DIR}/cavp.py"
    --path "$<TARGET_FILE_DIR:util_encrypt_block>")
add_test(NAME cavp_boxes COMMAND Python3::Interpreter
    "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/tools/ctest-driver.py"
    run
    --pass-regex [=[Succeeded: *96$]=]
    --fail-regex [=[Failed: *[1-9]]=]
    --
    "$<TARGET_FILE:Python3::Interpreter>"
    "${CMAKE_CURRENT_SOURCE_DIR}/cavp.py"
    --path "$<TARGET_FILE_DIR:util_encrypt_block>"
    --boxes)
add_test(NAME file COMMAND Python3::Interpreter
    "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/tools/ctest-driver.py"
    run
    --pass-regex [=[Succeeded: *180$]=]
    --fail-regex [=[Failed: *[1-9]]=]
    --
    "$<TARGET_FILE:Python3::Interpreter>"
    "${CMAKE_CURRENT_SOURCE_DIR}/file.py"
    --path "$<TARGET_FILE_DIR:util_encrypt_file>")
