# Ransomware
ONLY FOR EDUCATIONAL PURPOSE

A ransomware in C for a school project at Henallux.

# Compilation requirements
+ CMake: Min version 3.24
+ Build Tool: Min GNU Make 4.3
+ C Compiler: Min cc 11.3.0
+ C++ Compiler: c++ 11.3.0

# Dependencies
+ OpenSSL: Min 3.0.2
+ libssl-dev: Min 3.0.2
    
# Compilation
``[CMake_PATH]`` needs to be replaced with your cmake executable file in your installation folder.  
``[PROJECT_DIRECTORY]`` needs to be replaced with the path where you put the project.  
``[TYPE]`` needs to be replaced with the type you've chosen at the previous step : ``debug or release``.

## Debug
```
[CMake_PATH] -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" -S [PROJECT_DIRECTORY] -B [PROJECT_DIRECTORY]/cmake-build-debug
```

## Release
```
[CMake_PATH] -DCMAKE_BUILD_TYPE=Release -G "CodeBlocks - Unix Makefiles" -S [PROJECT_DIRECTORY] -B [PROJECT_DIRECTORY]/cmake-build-release
```

## Example
```
[CMake_PATH] -DCMAKE_BUILD_TYPE=Release -G "CodeBlocks - Unix Makefiles" -S /home/ubuntu/deployment -B /home/ubuntu/deployment/cmake-build-release
```
    
## Build 
```
[CMake_PATH] --build [PROJECT_DIRECTORY]/cmake-build-[TYPE] --target attacker -- -j 19
[CMake_PATH] --build [PROJECT_DIRECTORY]/cmake-build-[TYPE] --target victim -- -j 19
```

# Execution
``[PROJECT_DIRECTORY]`` needs to be replaced with the path where you put the project.  
``[TYPE]`` needs to be replaced with the type you've chosen at the previous step : ``debug or release``.

```
[PROJECT_DIRECTORY]/cmake-build-[TYPE]/src/attacker/attacker --help
[PROJECT_DIRECTORY]/cmake-build-[TYPE]/src/victim/victim --help
```

## Example
```
/home/ubuntu/deployment/cmake-build-release/src/attacker/attacker --help
/home/ubuntu/deployment/cmake-build-release/src/victim/victim --help
```      

# Project scoring
I got 16/20
Justin got 20/20
