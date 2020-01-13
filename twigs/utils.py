import os

def find_files(localpath, filename):
    ret_files = []
    for root, subdirs, files in os.walk(localpath):
        for fname in files:
            file_path = os.path.join(root, fname)
            if len(filename) == 0:
                ret_files.append(file_path)
            elif file_path.endswith(filename):
                ret_files.append(file_path)
    return ret_files

def ascii_string(in_str):
    ascii_str = ''.join([c if ord(c) < 128 else ' ' for c in in_str.strip()])
    return ascii_str

def get_indent(line):
    return len(line) - len(line.lstrip(' '))
