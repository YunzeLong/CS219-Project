file = None

def init(filename = 'middle_box.log'):
    global file
    file = open(filename, 'w')

def writeline(line: str):
    global file
    print(line)
    file.write(f'{line}\n')

def shutdown():
    global file
    file.close()
