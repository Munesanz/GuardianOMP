# GuardianOMP

## Build LLVM and OpenMP
(llvm project)

Install ninja build system and clang (optional):
```sh
sudo apt-get install ninja-build clang
export CC=/usr/bin/clang
export CXX=/usr/bin/clang++
```

Execute the following command with the desired installation PATH:

```sh
cd llvm
mkdir build
cd build
cmake -DLLVM_ENABLE_PROJECTS="clang;openmp" -DCMAKE_BUILD_TYPE=MinSizeRel -G "Ninja" -DCMAKE_INSTALL_PREFIX=${INS_PATH} -DLIBOMP_TASKGRAPH=1 ../llvm
ninja install
```

## Fault Injector

Fault injector can be compiled as a shared library:

```sh
gcc -O2 -shared -fPIC -o fault_injector.so fault_injector.c -lpthread
```

First, global data offsets and sizes of a binary can be extracted using "extract_object_file.sh"


```sh
./extract_object_file.sh binary
```

It will generate a file named "object_file.txt" containing all the offsets and sizes of global data. This file es read by the fault injector tool.

Then, to enable fault injection employ LD_PRELOAD env var:

```sh
LD_PRELOAD=fault_injector.so DELAY_TIME=1000 ./binary
```

Available env vars are: DELAY_TIME (miliseconds), MODE ("REGISER", "MEMORY" or "RANDOM), MEMORY_REGIONS ("HEAP", "DATA" or "STACK), REGISTERS and NUM_BITFLIPS.
