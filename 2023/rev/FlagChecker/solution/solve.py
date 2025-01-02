from z3 import *

s = Solver()

flag = []
for i in range(22):
    flag.append(BitVec(f"f_{i}", 8))


s.add(flag[18]* flag[7]& flag[12]^ flag[2]== 36)
s.add(flag[1]% flag[14]- flag[21]% flag[15]== -3)
s.add(flag[10]+ flag[4]* flag[11]- flag[20]== 5141)
s.add(flag[19]+ flag[12]* flag[0]^ flag[16]== 8332)
s.add(flag[9]^ flag[13]* flag[8]& flag[16]== 113)
s.add(flag[3]* flag[17]+ flag[5]+ flag[6]== 7090)
s.add(flag[21]* flag[2]^ flag[3]^ flag[19]== 10521)
s.add(flag[11]^ flag[20]* flag[1]+ flag[6]== 6787)
s.add(flag[7]+ flag[5]- flag[18]& flag[9]== 96)
s.add(flag[12]* flag[8]- flag[10]+ flag[4]== 8277)
s.add(flag[16]^ flag[17]* flag[13]+ flag[14]== 4986)
s.add(flag[0]* flag[15]+ flag[3]== 7008)
s.add(flag[13]+ flag[18]* flag[2]& flag[5]^ flag[10]== 118)
s.add(flag[0]% flag[12]- flag[19]% flag[7]== 73)
s.add(flag[14]+ flag[21]* flag[16]- flag[8]== 11228)
s.add(flag[3]+ flag[17]* flag[9]^ flag[11]== 11686)
s.add(flag[15]^ flag[4]* flag[20]& flag[1]== 95)
s.add(flag[6]* flag[12]+ flag[19]+ flag[2]== 8490)
s.add(flag[7]* flag[5]^ flag[10]^ flag[0]== 6869)
s.add(flag[21]^ flag[13]* flag[15]+ flag[11]== 4936)
s.add(flag[16]+ flag[20]- flag[3]& flag[9]== 104)
s.add(flag[18]* flag[1]- flag[4]+ flag[14]== 5440)
s.add(flag[8]^ flag[6]* flag[17]+ flag[12]== 7104)
s.add(flag[11]* flag[2]+ flag[15]== 6143)

for i in range(22):
    s.add(flag[i] >= 33)
    s.add(flag[i] <= 127)

print(s.check())
flag_arr = s.model()
print(flag_arr)

for i in range(0,22):
    print(chr(flag_arr.eval(eval(f'flag[{i}]')).as_long()),end='')