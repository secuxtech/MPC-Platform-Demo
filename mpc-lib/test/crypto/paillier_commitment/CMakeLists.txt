add_executable(paillier_commitment_test
    tests.cpp
)

target_compile_options(paillier_commitment_test PRIVATE -Wall -Wextra)
target_link_libraries(paillier_commitment_test PRIVATE tests_main)

add_test(NAME paillier_commitment_test COMMAND paillier_commitment_test)
