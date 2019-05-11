#!/bin/zsh
max_i=10000000
readonly gap=1000000
for ((i=100000;i<max_i;i=i+gap)){
    /usr/bin/time -o test.$i.time -a -p -f "\t%e" \
        ./build/main -d test.$i.addre \
        -f test.$i.func \
        -r test.$i.json \
        -e ./a.out $i&
}

return 0;