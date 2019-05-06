step_file="test.sign.step"
ans_file="test.sign.json"
addre_file="test.sign.addre"
func_file="test.sign.func"

rm $step_file
rm $ans_file
rm $addre_file
rm $func_file

x-terminal-emulator -x "zsh -c \"./build/main --single-step --final-file $ans_file --addre-file $addre_file --func-file $func_file -e $@\" "&

step_file="test.block.step"
ans_file="test.block.json"
addre_file="test.block.addre"
func_file="test.block.func"

rm $step_file
rm $ans_file
rm $addre_file
rm $func_file

 x-terminal-emulator -x "zsh -c \"./build/main               --final-file $ans_file --addre-file $addre_file --func-file $func_file -e $@\"" &
