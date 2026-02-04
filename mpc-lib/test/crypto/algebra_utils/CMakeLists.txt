add_executable(albegra_utils_test
    tests.cpp
)

target_compile_options(albegra_utils_test PRIVATE -Wall -Wextra)
target_link_libraries(albegra_utils_test PRIVATE tests_main)

add_test(NAME albegra_utils_test COMMAND albegra_utils_test)
