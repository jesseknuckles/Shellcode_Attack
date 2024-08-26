For this Project, I created a multistage shellcode attack, using python scripts to attack a vulnerable c file.

For tasks one and two, I found the return address of a function in the stack, using gdb, during a certain function's execution. I then replaced this value with the value of a certain
function found in libc, which was imported by the vulnerable c file.

For task three, I used a ROP chain to add more functionality to our attack. This ROP chain used gadgets found in libc to prepare the stack with proper arguments for the mprotect.
mprotect is used to make the heap executable.

For task 4, I wrote and added assembly code using a python module to the exploit string, after mprotect is called. The shellcode calls execve, with ls as the argument. When the
exploit is completed, the directory's contents are listed out.
