# A29K-IDA
AMD 29k Processor Plugin for IDA Pro

## References
Decoding is based on code from binutils/gdb. 
Namely opcodes/a29k-dis.c and include/opcodes/a29k.h using 
commit 7e4e2059b54428715c678c775e2ea0f83f0487d1 from git://sourceware.org/git/binutils-gdb.git

Instruction descriptions are from the "29K Family. 1990 Data Book" by Advanced Micro Devices.

## Handling Delayed Instructions
The processor has delayed branches, which cause the instruction after the delayed branch to be executed in a delay slot, before the actual branch happens.

We have two modes of handling this behaviour. One is to rewrite the control flow and explicitly reoder the control-flow graph such that the instructions are shown in the real execution order.
The other is to use the IDA Pro handling of delay slots, and to not rewrite the control flow, but to mark the end of basic blocks, so that IDA can delay the branch until the end of a block is reached.

