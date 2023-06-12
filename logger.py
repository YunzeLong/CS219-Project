file = None

def init(filename = 'middle_box.log'):
    file = open(filename, 'a')

def writeline(line: str):
    print(line)
    file.write(f'{line}\n')

def shutdown():
    file.close()
