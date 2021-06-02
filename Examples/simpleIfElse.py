
def test(a:int, b:int):
    if a > 10:
        if a > b:
            if b > a:
               return 0
            else:
                return 1
        elif b > 50:
            return 2
        else:
            return 3
    elif b > 100:
        return 4 
    else:
        return 5