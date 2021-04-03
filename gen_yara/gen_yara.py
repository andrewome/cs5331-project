import sys
import leb128
import ctypes

def gen_32bit_chunks(s):
    # Truncate hex string from left if not multiple of 32 bits (8 hex chars)
    if len(s) % 8 != 0:
        s = s[8 - len(s) // 8:]
    
    # Split into chunks of 32 bits
    return [s[i:i+8] for i in range(0, len(s), 8)]

def gen_64bit_chunks(s):
    # Truncate hex string from left if not multiple of 64 bits (16 hex chars)
    if len(s) % 16 != 0:
        s = s[16 - len(s) // 16:]
    
    # Split into chunks of 64 bits
    return [s[i:i+16] for i in range(0, len(s), 16)]

def sep_bytes(s):
    return ' '.join([s[i:i+2] for i in range(0, len(s), 2)])

def to_little_endian(s):
    num_bytes = len(s) // 2
    return sep_bytes(int(s, 16).to_bytes(num_bytes, 'little').hex())

def to_i32(s):
    v = ctypes.c_int32(int(s, 16)).value
    return sep_bytes('41' + leb128.i.encode(v).hex())

def to_i64_from_32bit(s):
    # If bytes were initialised as 32 bits, it may combine into 64 bits, and stored in reverse order....
    s = s[8:] + s[:8]
    return to_i64(s)

def to_i64(s):
    v = ctypes.c_int64(int(s, 16)).value
    return sep_bytes('42' + leb128.i.encode(v).hex())

def main():
    if len(sys.argv) < 3:
        print('Not enough arguments')
        print('Usage: python3 script.py rule_name magic_bytes')
        return
    
    # Clean input
    name = sys.argv[1].rstrip().lstrip()
    data = sys.argv[2].rstrip().lstrip().replace('0x', '').replace('\\x', '')
    
    # Output rule format
    out = f'rule {name}\n{{\n  strings:\n'
    
    # Output 8 bit chunks
    out += f'    $ = {{ {sep_bytes(data)} }}\n'

    # Output 32 bit little endian chunks
    chunk_32bit = gen_32bit_chunks(data)
    v = ' '.join([to_little_endian(i) for i in chunk_32bit])
    out += f'    $ = {{ {v} }}\n'

    # Output 64 bit little endian chunks
    chunk_64bit = gen_64bit_chunks(data)
    v = ' '.join([to_little_endian(i) for i in chunk_64bit])
    out += f'    $ = {{ {v} }}\n'

    # Output i32 instructions, account for up to 20 bytes of other instructions in between before declaring next magic bytes
    v = ' [0-20] '.join([to_i32(i) for i in chunk_32bit])
    out += f'    $ = {{ {v} }}\n'
    
    # In the case the 32 bits are allocated in reverse order
    v = ' [0-20] '.join([to_i32(i) for i in chunk_32bit[::-1]])
    out += f'    $ = {{ {v} }}\n'

    # Output i64 instructions, account for up to 20 bytes of other instructions in between before declaring next magic bytes
    v = ' [0-20] '.join([to_i64(i) for i in chunk_64bit])
    out += f'    $ = {{ {v} }}\n'

    # In case the 64 bits are allocated in reverse order
    v = ' [0-20] '.join([to_i64(i) for i in chunk_64bit[::-1]])
    out += f'    $ = {{ {v} }}\n'

    # In the case it was 32 bits merged into 64 bit but allocated in reverse order (true story btw)
    v = ' [0-20] '.join([to_i64_from_32bit(i) for i in chunk_64bit[::-1]])
    out += f'    $ = {{ {v} }}\n'

    # Output condition
    out += '\n  condition:\n    any of them\n}'

    # Output to file
    with open(f'{name}.rule', 'w', encoding='utf-8') as f:
        f.write(out)

    print(f'Output written to {name}.rule')
    
if __name__ == '__main__':
    main()