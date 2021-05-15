
def func_a(a: int):
    for i in range(5):
        a += 2
    a = 11
    if a > 10:
        return True
    else:
        return False


def func_b(b: int):
    if b > 13:
        return False
    else:
        return True