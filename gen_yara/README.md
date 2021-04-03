# Yara Rule Generator

Depending on how the algorithm was programmed in the source code, it may be found as instructions or as chunks of data in the memory, depending on the data type declared for the magic numbers. An array of uint8 data will be represented differently from uint32 and uint64 due to little endianness. Even as instructions, it may be inserted in the oppositie direction due to compiler design, so we have to compensate for that as well.
 
We can overcome this by generating all possible outcomes that the magic numbers may appear in the WebAssembly binary. Therefore we have written a python script which takes in an array of magic numbers bytes in big endian and generates a YARA rule based on the WebAssembly i32.const, i64.const WebAssembly instruction bytes and little endian uint8 data array, uint32 data array, uint64 data array as if the numbers were compiled into readable memory instead.

## Example
Command
```
python3 gen_yara.py test 0x0123456789abcdef
```
Output
```
rule test
{
  strings:
    $ = { 01 23 45 67 89 ab cd ef }  # 8 bit array
    $ = { 67 45 23 01 ef cd ab 89 }  # 32 bit
    $ = { ef cd ab 89 67 45 23 01 }  # 64 bit
    $ = { 41 e7 8a 8d 09 [0-20] 41 ef 9b af cd 78 }  # i32.const
    $ = { 41 ef 9b af cd 78 [0-20] 41 e7 8a 8d 09 }  # i32.const reversed
    $ = { 42 ef 9b af cd f8 ac d1 91 01 }  # i64.const
    $ = { 42 ef 9b af cd f8 ac d1 91 01 }  # i64.const reversed
    # Initially 32bits but converted into i64.const then placed in reverse order
    $ = { 42 e7 8a 8d 89 f0 bd f3 d5 89 7f }  

  condition:
    any of them
}
```

## convert_rules.py
Converts all rules in `rules` folder into a JavaScript array. Use this with the extension cause that's where the extension loads the rules from.

## run.sh
Bash script to generate all cryptonight rules, move them into `rules` folder and use `convert_rules.py` to convert them into a JavaScript file to be used with the extension.