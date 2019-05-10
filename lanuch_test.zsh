#!/bin/zsh
rm test.time 
echo "real\tuser\tsys" >> test.time
max_i=10000000
readonly gap=1000000
for ((i=100000;i<max_i;i=i+gap)){
    echo -n $i >> test.time
    /usr/bin/time -o test.time -a -p -f "\t%e" ./a.out $i
}
for ((i=100000;i<max_i;i=i+gap)){
    echo -n $i >> test.time
    /usr/bin/time -o test.time -a -p -f "\t%e" ./build/main -e ./a.out $i
}

return 0;

step_file="test.block.step"
ans_file="test.block.json"
addre_file="test.block.addre"
func_file="test.block.func"

rm $step_file
rm $ans_file
rm $addre_file
rm $func_file

 x-terminal-emulator -x "zsh -c \"./build/main              --final-file $ans_file --addre-file $addre_file --func-file $func_file -e $@ \" " &
