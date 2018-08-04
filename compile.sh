#!/bin/bash

if [ ! -d "peafowl_lib" ]; then
  echo "Clone Peafowl..."
  git clone https://github.com/DanieleDeSensi/Peafowl.git peafowl_lib
fi

if [ ! -f peafowl_lib/lib/libdpi.a ]; then
  echo "Compiling Peafowl..."
  make -C peafowl_lib
  echo "Peafowl lib ready!"
fi

if [ -d "build" ]; then
  rm -rf build
fi

