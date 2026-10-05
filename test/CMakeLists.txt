find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(test_run
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/cmake"
    COMMAND Python3::Interpreter
    -m project.ctest_driver
    run
)

add_test(NAME nist ${test_run}
    --pass-regex [=[Succeeded: *30$]=]
    --fail-regex [=[Failed: *[1-9]]=]
    --
    "$<TARGET_FILE:Python3::Interpreter>"
    "${CMAKE_CURRENT_SOURCE_DIR}/nist.py"
    --path "$<TARGET_FILE_DIR:util_encrypt_block>"
)
add_test(NAME cavp ${test_run}
    --pass-regex [=[Succeeded: *96$]=]
    --fail-regex [=[Failed: *[1-9]]=]
    --
    "$<TARGET_FILE:Python3::Interpreter>"
    "${CMAKE_CURRENT_SOURCE_DIR}/cavp.py"
    --path "$<TARGET_FILE_DIR:util_encrypt_block>"
)
add_test(NAME file ${test_run}
    --pass-regex [=[Succeeded: *180$]=]
    --fail-regex [=[Failed: *[1-9]]=]
    --
    "$<TARGET_FILE:Python3::Interpreter>"
    "${CMAKE_CURRENT_SOURCE_DIR}/file.py"
    --path "$<TARGET_FILE_DIR:util_encrypt_file>"
)
