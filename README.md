# GuardianOMP Tool

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
mkdir build
cd build
cmake -DLLVM_ENABLE_PROJECTS="clang;openmp" -DCMAKE_BUILD_TYPE=MinSizeRel -G "Ninja" -DCMAKE_INSTALL_PREFIX=${INS_PATH} ../llvm
ninja install
```

## Fault Sim

FaultSim can be compiled as a shared library:

```sh
gcc -O2 -shared -fPIC -o fault_sim.so fault_sim.c -lpthread -ldl
```

First, global data offsets and sizes of a binary can be extracted using "extract_object_file.sh"


```sh
./extract_object_file.sh binary
```

It will generate a file named "object_file.txt" containing all the offsets and sizes of global data. This file is read by FaultSim.

Then, to enable it employ LD_PRELOAD env var:

```sh
LD_PRELOAD=fault_sim.so DELAY_TIME=1000 ./binary
```

Others available env vars are: DELAY_TIME (miliseconds), MODE ("REGISTER", "MEMORY" or "RANDOM"), MEMORY_REGIONS ("HEAP", "DATA" or "STACK), REGISTERS and NUM_BITFLIPS.
