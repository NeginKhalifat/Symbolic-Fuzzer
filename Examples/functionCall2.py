def func1(a: int):
    a = 13
    if a > 14:
        a = 2
    elif func2(a):
        a = 4


def func2(b: int):
    b = 12
    if b > 14:
        a: int = 2
    else:
        return func3(b)


def func3(c: int):
    b: int = 12
    if c > b:
        a: int = 2
    else:
        b = c
    return b
