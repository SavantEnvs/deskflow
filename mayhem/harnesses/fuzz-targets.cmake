# Injected into upstream's CMake run by mayhem/build.sh (CMAKE_PROJECT_deskflow_INCLUDE), so the fuzz
# harnesses are ordinary targets in upstream's own build and link its static libraries with their
# usage requirements (Qt, OpenSSL, X11, libei, ...). Nothing upstream is edited.
# The targets are defined once upstream's whole tree has been read (cmake_language DEFER).
# (EVAL so the path is expanded now: a deferred call expands its arguments only when it runs.)
cmake_language(EVAL CODE
  "cmake_language(DEFER DIRECTORY \"${CMAKE_SOURCE_DIR}\" CALL include \"${CMAKE_CURRENT_LIST_DIR}/fuzz-targets-defs.cmake\")"
)
