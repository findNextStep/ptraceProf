#!/bin/zsh
max_i=100000000
readonly gap=1000000
for ((i=gap;i<max_i;i=i+gap)){
    /usr/bin/time -o test.d.time -a -p -f "\t%e" \
        ./build/main \
        -e ./a.out $i
        # -e ./a.out $i&
        # -d test.$i.addre \
        # -f test.$i.func \
        # -r test.$i.json \
}

return 0;
