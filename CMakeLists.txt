cmake_minimum_required (VERSION 3.8)

project(MHWSafeNet VERSION "0.0.1")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(extern)

add_library(MHWSafeNet SHARED
	"src/main.cpp"
	"src/SigScan.hpp"
	"src/SigScan.cpp"
	"src/Mt.hpp"
	"src/size_assert.hpp"
   "src/strackeror_logger.h")
  
target_include_directories (MHWSafeNet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(MHWSafeNet PUBLIC fmt::fmt)
target_link_libraries(MHWSafeNet PUBLIC spdlog::spdlog)
target_link_libraries(MHWSafeNet PUBLIC minhook)


