[toc] 
# 概述
操作系统（英语：operating system，缩写：OS）是管理计算机硬件与软件资源的计算机程序，同时也是计算机系统的内核与基石。操作系统需要处理如管理与配置内存、决定系统资源供需的优先次序、控制输入与输出设备、操作网络与管理文件系统等基本事务。操作系统也提供一个让用户与系统交互的操作界面。
计算机操作系统原理课程是计算机科学与技术及相关专业的核心课程之一，对理论与实践要求都很高，历来为计算机及信息学科所重视。操作系统课程设计正是该课程实践环节的集中表现，不仅可使学生巩固理论学习的概念、原理、设计、算法及数据结构，同时培养开发大型软件所应拥有的系统结构设计和软件工程素养。对该课程考核体系的构建可以促进学 生设计能力、创新能力和科学素养的全面提升。
#	实验环境
实验代码|	GeekOS-0.3.0
----|------
硬件模拟器 |	BOCHS x86 Emulator 2.3.7
Linux操作系统 |	Linux发行版Ubuntu9.04
虚拟机 |	Vmware12.5.7 build-5813279
主机系统 |	Windows10,64-bit
计算机硬件 |	X86 PC

## GeekOS-0.3.0
基于X86的GeekOS教学型类Linux操作系统.GeekOS主要用于操作系统课程设计,目的是使学生能够实际动手参与到一个操作系统的开发工作中学生可以在Linux或Unix环境或/windows下使用BochsPC模拟器进行开发,且其针对进程、文件系统、存储管理等操作系统核心内容分别设计了7个难度逐渐增加的项目供教师选择.出于教学目的,这个系统内核设计简单,让学生易于阅读、设计和添加代码,但它又涵盖了操作系统课程的核心内容,能够满足操作系统课程教学的需求,却又兼备实用性,它可以运行在真正的X86PC硬件平台.GeekOS由一个基本的操作系统内核作为基础,已经实现如下功能:
(1)	操作系统与硬件之间的所有必备接口。

(2)	系统引导、实模式到保护模式的转换、中断调用及异常处理。

(3)	基于段式的内存管理。

(4)	内核进程以及FIFO进程调度算法。

(5)	基本的输入输出:键盘作为输入设备,显示器作为输出设备。

(6)	只读文件系统PFAT:用于存放用户程序。

目前，除上述所列的之外，还缺少虚拟内存、存储设备驱动和文件系统。在GeekOS中，使用分段机制实现了用户模式任务的内存保护。为了克服在存储设备和文件系统方面的欠缺，GeekOS提供了一个种机制以实现将用户程序编译成直接链接内核的数据对象。这种技术也可以用来实现基于RAM的文件系统。
##	Bochs和Vmware介绍
Bochs是一个x86硬件平台的开源模拟器。它可以模拟各种硬件的配置。Bochs模拟的是整个PC平台，包括I/O设备、内存和BIOS。更为有趣的是，甚至可以不使用PC硬件来运行Bochs。事实上，它可以在任何编译运行Bochs的平台上模拟x86硬件。通过改变配置，可以指定使用的CPU(386、486或者586)，以及内存大小等。一句话，Bochs是电脑里的“PC”。根据需要，Bochs还可以模拟多台PC，此外，它甚至还有自己的电源按钮。
VMWare虚拟机软件是一个“虚拟PC”软件，它使你可以在一台机器上同时运行二个或更多Windows、DOS、LINUX系统。与“多启动”系统相比，VMWare采用了完全不同的概念。多系统在一个时刻只能运行一个系统，在系统切换时需要重新启动机器。
## 开发过程
为顺利的进行课程设计开发，避免出现软件版本不兼容导致一系列问题，使用了指导老师提供的虚拟机镜像以及虚拟机软件Vmware，虚拟机操作系统为Ubuntu9，其中包含了一份geekOS源码，以及安装好的Bochs硬件模拟器。
### 编译运行
编译方法为在终端中进入每个Project下的build目录，先输入make depend，生成depend.mak文件，目的是链接头文件，为了快速的进行编译。然后输入make，使用gcc编译读取文件夹下的Makefile对源码进行编译。编译完成后在对应的文件夹下生成后缀为.o文件，根据.o文件生成fd.img系统镜像文件。同时在project1-4也生成了运行镜像的文件系统diskc.img。
生成系统镜像后使用Bochs进行模拟硬件平台，引导运行系统镜像，方法为在终端中进入Project下的build目录，输入bochs就可以直接运行。
###	配置文件
在Bochs引导系统镜像运行过程中需要配置描述模拟器硬件配置的配置文件。文件内容如下。
Project0所需的.bochs文件

```
megs: 8
boot: a
floppya: 1_44=fd.img, status=inserted
log: ./bochs.out
#Project0 1-4还需要ata串口驱动器，需要加上：
ata0-master: type=disk, path=diskc.img, mode=flat, cylinders=40, heads=8, spt=64
```
# 前导知识

## 一、全局描述符表GDT（Global Descriptor Table）
 在整个系统中，全局描述符表GDT只有一张(一个处理器对应一个GDT)，GDT可以被放在内存的任何位置，但CPU必须知道GDT的入口，也就是基地址放在哪里，Intel的设计者门提供了一个寄存器GDTR用来存放GDT的入口地址，程序员将GDT设定在内存中某个位置之后，可以通过LGDT指令将GDT的入口地址装入此积存器，从此以后，CPU就根据此寄存器中的内容作为GDT的入口来访问GDT了。GDTR中存放的是GDT在内存中的基地址和其表长界限。
## 二、段选择子（Selector）
访问全局描述符表是通过“段选择子” 来完成的。段选择子共计16位，如图：
![Selector](https://img-blog.csdn.net/20180419153235885?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhY2FjYWk=/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)
段选择子包括三部分：描述符索引（index）、TI、请求特权级（RPL）。index（描述符索引）部分表示所需要的段的描述符在描述符表的位置，由这个位置再根据在GDTR中存储的描述符表基址就可以找到相应的LDT描述符。段选择子中的TI值只有一位0或1，0代表选择子是在GDT，1代表选择子是在LDT。请求特权级（RPL）则代表选择子的特权级，共有4个特权级（0级、1级、2级、3级）。

## 三、局部描述符表LDT（Local Descriptor Table）

   ![LDT](https://img-blog.csdn.net/20180419153222867?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhY2FjYWk=/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)
## 四、CPU访问控制
   Intel的x86处理器是通过Ring级别来进行访问控制的，级别共分4层，从Ring0到Ring3（后面简称R0、R1、R2、R3）。R0层拥有最高的权限，R3层拥有最低的权限。按照Intel原有的构想，应用程序工作在R3层，只能访问R3层的数据；操作系统工作在R0层，可以访问所有层的数据；而其他驱动程序位于R1、R2层，每一层只能访问本层以及权限更低层的数据。

这样操作系统工作在最核心层，没有其他代码可以修改它；其他驱动程序工作在R1、R2层，有要求则向R0层调用，这样可以有效保障操作系统的安全性。但现在的OS，包括Windows和Linux都没有采用4层权限，而只是使用2层——R0层和R3层，分别来存放操作系统数据和应用程序数据，


#	项目设计
##	Project0
### 	项目设计目的
熟悉GeekOS的项目编译、调试和运行环境，掌握GeekOS运行的工作过程。
###	项目设计要求
(1)	搭建GeekOS的编译和调试平台，掌握GeekOS的内核进程工作原理。

(2)	熟悉键盘操作函数，编程实现一个内核进程。此进程的功能是：接收键盘输入的字符并显示到屏幕上，当输入“Ctrl+D”时，结束进程的运行。

3.1.3	项目设计原理
键盘设备驱动程序提供了一系列的高级接口来使用键盘。键盘事件的逻辑关系为：用户按键引发键盘中断，根据是否按下键，分别在键值表中寻找扫描码对应的按键值，经过处理后将键值放入键盘缓冲区s_queue中，最后通知系统重新调度进程。


若用户进程需要从键盘输入信息，可调用Wait_For_Key()函数,该函数首先检查键盘缓冲区是否有按键。如果有，就读取一个键码，如果此时键盘缓冲区中没有按键，就将进程放入键盘事件等待队列s_waitQueue，由于按键触发了键盘中断，键盘中断处理函数Keyboard_Interrupt_Handler就会读取用户按键，将低级键扫描码转换为含ASCII字符的高级代码，并刷新键盘缓冲区，最后唤醒等待按键的进程继续运行。
###	项目设计代码
(1)	编写一个函数，此函数的功能是：接收键盘输入的字符并显示到屏幕上，当输入“Ctrl+D”时就退出。函数代码如下：

```
void EchoCount()
{
Keycode keycode;
    while (1)
    {
        if ( Read_Key( &keycode ) )
        {
            if((keycode & 0x4000) == 0x4000)
            {
                if((Wait_For_Key() & 0x00ff) == 'd')
{
                    Set_Current_Attr(ATTRIB(BLACK, RED));
                    Print("Ctrl+d Is Entered! Program Ended!");
                    Exit(1);
                }
           }
           else if ( !(keycode & KEY_SPECIAL_FLAG) &&  !(keycode & KEY_RELEASE_FLAG) )    
           {
               keycode &= 0xff; 
               Set_Current_Attr(ATTRIB(BLACK, CYAN));
               Print( "%c", (keycode == '\r') ? '\n' : keycode );
               if(keycode=='\r')
               {              
                   Set_Current_Attr(ATTRIB(AMBER, BLUE));
               }
           }
       }
   }
}
```

(2)	在Main函数体内调用Start_Kernel_Thread函数，将以上函数地址传递给参数startFunc，建立一个内核级进程。相关代码如下：
```
struct Kernel_Thread *kerThd;
kerThd = Start_Kernel_Thread(&EchoCount, 0 , PRIORITY_NORMAL, false);

```
###	运行结果
对项目进行编译生成系统镜像，然后使用bochs运行系统镜像，测试结果如图3-1所示，运行。
 
图 3 1
##	Project1
###	项目设计目的
熟悉ELF文件格式，了解GeekOS系统如何将ELF格式的可执行程序装入到内存，建立内核进程并运行的实现技术。
###	项目设计要求
修改/geekos/elf.c文件，在函数Parse_ELF_Executable()中添加代码，分析ELF格式的可执行文件（包括分析得出ELF文件头、程序头，获取可执行文件长度，代码段、数据段等信息），并填充Exe_Format数据结构中的域值。
###	项目设计原理
(1)	ELF文件格式
Executable and linking format(ELF)文件是x86 Linux系统下的一种常用目标文件(object file)格式，有三种主要类型:
①	适于连接的可重定位文件(relocatable file)，可与其它目标文件一起创建可执行文件和共享目标文件。
②	适于执行的可执行文件(executable file)，用于提供程序的进程映像，加载的内存执行。
③	共享目标文件(shared object file)，连接器可将它与其它可重定位文件和共享目标文件连接成其它的目标文件，动态连接器又可将它与可执行文件和其它共享目标文件结合起来创建一个进程映像。
为了方便和高效，ELF文件内容有两个平行的视图:一个是程序连接角度，另一个是程序运行角度。GeekOS中的用户程序全部在系统的编译阶段完成编译和连接，形成可执行文件，用户可执行文件保存在PFAT文件系统中，如图所示。
在Parse_ELF_Executable函数中，此函数的作用为根据ELF文件格式，从exeFileData指向的内容中得到ELF文件头，继续分析可得到程序头和程序代码段等信息。
连接程序视图 |执行程序视图 
-----|--
ELF头部|	ELF 头部
程序头部表（可选）|	程序头部表
节区1|	段1
...	|段1
节区n|	段2
...	|段2
...	|...
节区头部表	节区头部表（可选）
(2)	建立线程过程如图3 2所示
 ![建立线程](https://img-blog.csdn.net/2018041915475560?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhY2FjYWk=/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)
图 3 2
具体流程为在geek/main.c中的main函数中Spawn_Init_Process()然后跳转到函数Start_Kernel_Thread(Spawner, 0, PRIORITY_NORMAL, true)，该函数中的第一个参数为启动lprog.c中的函数Spwaner()，然后使用Read_Fully()读取提前编译好c.exe文件，并返回可执行文件elf数据和长度，然后使用自己编写的Parse_ELF_Executable()函数，对读取到的elf文件进行分析，得出ELF文件头、程序头，获取可执行文件长度，代码段、数据段等信息。然后在函数Spawn_Progrm()中，分配内存，通过Trampoline函数模拟执行用户态进程。
###	项目设计代码
```
int Parse_ELF_Executable(char *exeFileData, ulong_t exeFileLength,
    struct Exe_Format *exeFormat)
{
int i;
    elfHeader *head = (elfHeader*)exeFileData;
    programHeader *proHeader = (programHeader *)(exeFileData+head->phoff);
    KASSERT(exeFileData != NULL);
    KASSERT(exeFileLength > head->ehsize+head->phentsize*head->phnum);
    KASSERT(head->entry%4 == 0);
    exeFormat->numSegments = head->phnum;
    exeFormat->entryAddr = head->entry;
    for(i=0; i<head->phnum; i++)
{
        exeFormat->segmentList[i].offsetInFile = proHeader->offset;
        exeFormat->segmentList[i].lengthInFile = proHeader->fileSize;
        exeFormat->segmentList[i].startAddress = proHeader->vaddr;
        exeFormat->segmentList[i].sizeInMemory = proHeader->memSize;
        exeFormat->segmentList[i].protFlags = proHeader->flags;
        proHeader++;
}
return 0;
}
```


##	运行结果
结果如图3-4所示，成功读取a.exe文件并运行其中的代码。
 
图 3 4
##	Project2
###	项目设计目的
扩充GeekOS操作系统内核，使得系统能够支持用户级进程的动态创建和执行。
###	项目设计要求
本项目要求用户对以下/src/geekos/中的文件进行修改：
: (1)	user.c：完成函数Spawn()和Switch_To_User_Context()。//*创建进程，切换用户上下文*

: (2)	elf.c：完成函数Parse_ELF_Executable()，要求与项目1相同。//*分析exe文件，用于上下文（context）*
: (3)	userseg.c：完成函数Destroy_User_Context()、Load_User_Program()、Copy_From_User()、Copy_To_User()和: Switch_To_Address_Space()。//*销毁用户进程上下文，加载用户进行，切换用户地址空间，用来进出内核操作*
: (4)	kthread.c：完成函数Setup_User_Thread()和Start_User_Thread()。*//设置，启动进程，进入等待队列*
: (5)	syscall.c：完成函数Sys_Exit()、Sys_PrintString()、Sys_GetKey()、Sys_SetAttr()、Sys_GetCursor()、: Sys_PutCursor()、Sys_Spawn()、Sys_Wait()和Sys_GetPID()。*//系统调用函数，方便用户进程执行内核操作，以及只有内核才有的权限操作，如创建进程，进行系统调用需要进入内核空间使用（3）中的函数*
: (6)	main.c：改写Spawn_Init_Process(void)，改写时将“/c/shell.exe”作为可执行文件传递给Spawn函数的program参数，创建第一个用户态进程，然后由它来创建其它进程。
开始本项目前需要阅读/src/geekos目录中的entry.c、lowlevel.asm、kthread.c、userseg.c，其中在userseg.c中主要关注Destroy_User_Context()和Load_User_Program()两个函数。
###	项目设计原理
进程是可并发执行的程序在某个数据集合上的一次计算活动，也是操作系统资源分配和保护的基本单位。进程和程序有着本质的区别，程序是一些能保存在磁盘上的指令的有序集合，没有任何执行的概念；而进程是程序执行的过程，包括了创建、调度和消亡的整个过程。因此，对系统而言，当用户在系统中输入命令执行一个程序时，它将启动一个进程。

在GeekOS中，进程的执行过程分为运行态、就绪态和等待态。
GeekOS为不同状态的进程准备了不同的进程队列
(Thread_Queue)。如果一个进程正处于就绪态，就会在队列s_runQueue中出现；如果一个进程处于等待态，就会在s_reaperWaitQueue队列中出现；如果一个进程准备被销毁，就会在s_graveyardQueue队列中出现。由于处于运行态的进程最多只能有一个，所以没有队列，由指针g_currentThread指向此进程。


系统中每个进程有且仅有一个进程控制块(PCB)，它记录了有关进程的所有信息，GeekOS的PCB用数据结构Kernel_Thread来表示。GeekOS最早创建的内核级进程是Idle、Reaper和Main。GeekOS在几种情况下会进行进程切换：一是时间片用完时；二是执行进程Idle时；三是进程退出调用Exit函数时；四是进程进入等待态调用Wait函数时。如图3-5所示。用户进程切换通过Switch_To_User_Context函数实现，此函数负责检测当前进程是否为用户级进程，若是就切换至用户进程空间，它由我们自己实现。
![cpu](https://img-blog.csdn.net/20180419160617728?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhY2FjYWk=/font/5a6L5L2T/fontsize/100/fill/I0JBQkFCMA==/dissolve/70)
图 3 5
在GeekOS中为了区分用户级进程与内核级进程，在Kernel_Thread结构体中设置了一个字段userContext，它指向用户态进程上下文。对于内核级进程来说，此指针为空。因此，要判断一个进程是用户级的还是内核级的，只要判断userContext字段是否为空就行了。新建和注销User_Context结构的函数分别是Create_User_Context函数和Destroy_User_Context函数，它们都由我们自己实现。


每个用户态进程都要占用一段物理上连续的内存空间，存储用户级进程的数据和代码。所以，为了实现存取访问控制，每个用户级进程都有属于自己的内存段空间，每一个段有一个段描述符，并且每一个进程都有一个段描述符表(LDT)，它用于保存此进程的所有段描述符。

为用户级进程创建LDT的步骤是：
: (1)	调用Allocate_Segment_Descriptor()新建一个LDT描述符；
: (2)	调用Selector()新建一个LDT选择子；
: (3)	调用Init_Code_Segment_Descriptor()新建一个文本段描述符；
: (4)	调用Init_Data_Segment_Descriptor()新建一个数据段描述符；
: (5)	调用Selector()新建一个数据段选择子；
: (6)	调用Selector()新建一个文本段选择子。
在用户态进程首次被调度前，系统必须初始化用户态进程的堆栈，使之看上去像进程刚被中断运行一样，因此需要使用Push函数将以下数据压入堆栈：数据选择子、堆栈指针、Eflags、文本选择子、程序计数器、错误代码、中断号、通用寄存器、DS寄存器、ES寄存器、FS寄存器和GS寄存器。

GeekOS的用户级进程创建过程可以描述如下：
: (1)	Spawn函数导入用户程序并初始化：调用Load_User_Program进行User_Context的初始化及用户级进程空间的分配及: 用户程序各段的装入；
: (2)	Spawn函数调用Start_User_Thread()，初始化一个用户态进程，包括初始化进程Kernel_Thread结构以及调用Setup_User_Thread初始化用户级进程内核堆栈；
: (3)	最后Spawn函数退出，这时用户级进程已被添加至系统运行进程队列，可以被调度了。
具体运行过程为在main.c调用函数Spawn(),使用shell.c建立第一个用户态进程，该进程的作用为一直等待读取用户输入指令，然后根据指令读取文件系统中的对应.exe文件，通过系统调用方法来建立用户进程，因为shell进程为用户进程，没有权限分配内存以及其他资源建立进程，只有内核才有权限，所以需要通过系统调用提供建立进程方法，以及读取进程pid方法。同时在切换到内核时候，需要把在用户级进程数据复制进内核栈进行继续操作。
###项目设计代码
部分代码，其余详见附录。

```
int Spawn(const char *program, const char *command, struct Kernel_Thread **pThread)
{
    /*
     * Hints:
     * - Call Read_Fully() to load the entire executable into a memory buffer
     * - Call Parse_ELF_Executable() to verify that the executable is
     *   valid, and to populate an Exe_Format data structure describing
     *   how the executable should be loaded
     * - Call Load_User_Program() to create a User_Context with the loaded
     *   program
     * - Call Start_User_Thread() with the new User_Context
     *
     * If all goes well, store the pointer to the new thread in
     * pThread and return 0.  Otherwise, return an error code.
     */
    /* Por Victor Rosales */
    char *exeFileData = 0;
    ulong_t exeFileLength = 0;
    struct Exe_Format exeFormat;
    struct User_Context *userContext = NULL;
    struct Kernel_Thread *process = NULL;
    int ret = 0;
	//ret 函数运行返回的结果，判断该函数是否正常运行

	//将整个可执行文件加载到内存缓冲区中
    ret = Read_Fully(program, (void**) &exeFileData, &exeFileLength);
    if (ret != 0) {
        ret = ENOTFOUND;
        goto error;
    }

	//验证可执行的有效性，读出运行文件结构
    ret = Parse_ELF_Executable(exeFileData, exeFileLength, &exeFormat);
    if (ret != 0) {
        ret = ENOEXEC;
        goto error;
    }
    //通过加载可执行文件镜像创建新进程的User_Context结构
    //调用Load_User_Program将可执行程序的程序段和数据段装入内存
    ret = Load_User_Program(exeFileData, exeFileLength, &exeFormat,
                            command, &userContext);
    if (ret != 0) {
        ret = -1;
        goto error;
    }
	//调用Start_User_Thread函数创建一个进程并使其进入准备运行队列
    process = Start_User_Thread(userContext, false);
    if (process == NULL) {
        ret = -1;
        goto error;
    }
    *pThread = process;
    ret =(*pThread)->pid;
error:
    if (exeFileData)
        Free(exeFileData);
    exeFileData = 0;
    return ret;
}
void Switch_To_User_Context(struct Kernel_Thread* kthread, struct Interrupt_State* state)
{
    /*
     * Hint: Before executing in user mode, you will need to call
     * the Set_Kernel_Stack_Pointer() and Switch_To_Address_Space()
     * functions.
     */
    if (kthread->userContext != NULL) {
		//切换用户地址空间
        Switch_To_Address_Space(kthread->userContext);
		
        Set_Kernel_Stack_Pointer(((ulong_t) kthread->stackPage) + PAGE_SIZE);
    }
}
```

###	运行结果
如图3 7所示，启动项目后，首先建立shell进程进程pid为6，然后创建b，c进程。再创建一个shell进程，再shell进程输入pid输出的是目前shell进程的进程号，因为之前以及建立了b，c进程，所以第二个shell进程pid为9。
 
图 3 7

##	Project3
###	项目设计目的
研究进程调度算法，掌握用信号量实现进程间同步的方法。为GeekOS扩充进程调度算法——基于时间片轮转的进程多级反馈调度算法，并能用信号量实现进程协作。
###	项目设计要求
实现src/geekos/syscall.c文件中的Sys_SetSchedulingPolicy系统调用，它的功能是设置系统采用的何种进程调度策略；
实现src/geekos/syscall.c文件中的Sys_GetTimeOfDay系统调用，它的功能是获取全局变量g_numTicks的值；
实现函数Change_Scheduling_Policy()，具体实现不同调度算法的转换。
实现syscall.c中信号量有关的四个系统调用：sys_createsemaphore()、sys_P()、sys_V()和sys_destroysemaphore()。
###	项目设计原理
(1)	多级反馈队列调度队列模型
如图3 10和3 11所示。
 ![这里写图片描述](https://img-blog.csdn.net/20180419161058770?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhY2FjYWk=/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)
图 3 10
 ![line](https://img-blog.csdn.net/20180419161107901?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhY2FjYWk=/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)
图 3 11
(2)	多级反馈队列与分时调度进程队列的转换
通过把多级反馈队列中的所有队列合并成一个队列，实现切换到分时调度队列。Get_Next_Runable()函数会自动选择优先级最高的队列，如图3-12所示。
 ![分时调度](https://img-blog.csdn.net/20180419161543217?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhY2FjYWk=/font/5a6L5L2T/fontsize/100/fill/I0JBQkFCMA==/dissolve/50)
图 3 12
(3)	函数设计提示
①	添加函数Chang_Scheduling_Policy(int policy, int quantum),policy是设置的调度策略，quantum是设置的时间片。例如policy为1说明设置的是多级反馈队列调度算法，此时若g_SchedPolicy（为系统添加的标识算法的变量，初始化为0）为0，说明当前的调度算法为轮转调度，要变成MLF就必须把空闲线程放入3队列，若g_SchedPolicy为1，说明当前是多级反馈队列调度算法，则返回。如果policy为0，则说明设置的是轮转调度，此时若g_SchedPolicy为1，则必须把4个队列变成一个队列，即所有的线程都在队列0上了。若g_SchedPolicy为0，则返回。
②	在系统调用Sys_GetTimeOfDay（）中，只需要返回g_numTicks就可以了。在Sys_SetSchedulingPolicy（）中，如果state->ebx是1，则设置的是MLF算法，调用Change_Scheduling_Policy(SCHED_RR,quantum)，为0则是RR算法，调用Change_Scheduling_Policy(SCHED_MLF,quantum)。如果state->ebx为其他值，则返回-1。
③	在Init_Thread（）中都是把队列放在0队列上的，并且blocked变量为false。
④	在Get_Next_Runnable（）中，从最高级的队列开始，调用Find_Best（）来找线程优先级最大的线程，直到在某级队列中找到符合条件可以运行的线程。
⑤	在Wait（）函数中，线程被阻塞，所以blocked变量被设置为true，并且如果是MLF算法，则该进程的currentReadyQueue加一，下次运行的时候进入高一级的线程队列。
(4)	信号量定义
GeekOS定义了信号量的结构体：
```
struct Semaphore{
     int semaphoreID;                /*信号量的ID*/
     char *semaphoreName;            /*信号量的名字*/
     int value;                      /*信号量的值*/
     int registeredThreadCount;       /*注册该信号量的线程数量*/
     struct Kernel_Thread *registeredThreads[MAX_REGISTERED_THREADS];
/*注册的线程*/
     struct Thread_Queue waitingThreads;    /*等待该信号的线程队列*/
     DEFINE_LINK(Semaphore_List,Semaphore);  /*连接信号链表的域*/
     }
```
(5)	信号量PV操作

```
信号量操作：
Semaphore_Create( )（创建信号量）
Semaphore_Acquire（P操作）
Semaphore_Release（V操作）
Semaphore_Destroy( )（销毁信号量）
Create_Semaphore（）函数首先检查请求创建的这个信号量的名字是否存在，如果存在，
那么就把这个线程加入到这个信号量所注册的线程链表上；
如果不存在，则分配内存给新的信号量，清空它的线程队列，
把当前的这个线程加入到它的线程队列中，设置注册线程数量为1，
初始化信号量的名字，值和信号量的ID，并把这个信号量添加到信号量链表上，最后返回信号量的ID。
```


###	项目设计代码

```
static int Sys_SetSchedulingPolicy(struct Interrupt_State* state)
{
	if (state->ebx != ROUND_ROBIN && state->ebx != MULTILEVEL_FEEDBACK)
		return -1;
	g_schedulingPolicy = state->ebx;
	g_Quantum = state->ecx;
	return 0;
}
static int Sys_GetTimeOfDay(struct Interrupt_State* state)
{
	return g_numTicks;
}

struct Kernel_Thread* Get_Next_Runnable(void)
{
	struct Kernel_Thread* best = 0;
	int i, best_index_queue = -1;

	if (g_schedulingPolicy == ROUND_ROBIN) {
		struct Kernel_Thread* best_in_queue = NULL;

		for (i = 0; i < MAX_QUEUE_LEVEL; i++){
			best_in_queue = Find_Best(&s_runQueue[i]);
			if (best == NULL) {
				best = best_in_queue;
				best_index_queue = i;
			} else if (best_in_queue != NULL){
					if (best_in_queue->priority > best->priority) {
						best = best_in_queue;
						best_index_queue = i;
					}
			}
		}
	} else if (g_schedulingPolicy == MULTILEVEL_FEEDBACK) {
		if ( g_currentThread->priority != PRIORITY_IDLE ){
			if ( g_currentThread->blocked && g_currentThread->currentReadyQueue > 0 ) 
				g_currentThread->currentReadyQueue--;
		}
		for (i = 0; i < MAX_QUEUE_LEVEL; i++){
			best = Find_Best(&s_runQueue[i]);
			best_index_queue = i;
			if (best != NULL)
				break;
		}
		if ( best->currentReadyQueue < MAX_QUEUE_LEVEL-1 )
			best->currentReadyQueue++;

	}
	KASSERT(best != NULL);
	Remove_Thread(&s_runQueue[best_index_queue], best);
	return best;
}

static int Sys_CreateSemaphore(struct Interrupt_State* state)
{
		int rc;
		char *name = 0;
		//int exit, id_sem;
		struct Semaphore *s=s_sphlist.head;

		if ((rc = Copy_User_String(state->ebx, state->ecx, VFS_MAX_PATH_LEN, &name)) != 0 ) 
        		goto fail; 
		//Print("Copy_User_String_Name =%s\n",name);
		while(s!=0)
		{
		//Print("whiles->semaphoreName=%s\n",s->semaphoreName);			
			if(strcmp(s->semaphoreName,name)==0)
			{
				s->registeredThreads[s->registeredThreadCount]=g_currentThread;
				s->registeredThreadCount+=1;
				return s->semaphoreID;
			}
			s=Get_Next_In_Semaphore_List(s);
		}
		s=(struct Semaphore *)Malloc(sizeof(struct Semaphore));
		s->registeredThreads[0]=g_currentThread;
		s->registeredThreadCount=1;
		//strcpy(s->semaphoreName,name);
		s->semaphoreName=name;
		//Print("s->semaphoreName=name===%s\n",s->semaphoreName);
		Clear_Thread_Queue(&s->waitingThreads);
		s->value=state->edx;
		s->semaphoreID=semnub;
		semnub++;
		Add_To_Back_Of_Semaphore_List(&s_sphlist,s);
		
		return s->semaphoreID;	
fail:
	Print("CreateSemaphore failed!");
	return -1;
}

static int Sys_P(struct Interrupt_State* state)
{
	struct Semaphore *s=s_sphlist.head;		
	while(s!=0)
	{ 
		if(s->semaphoreID == state->ebx)
			break;					
		s=Get_Next_In_Semaphore_List(s);				
	}
	if(s==0)
		return -1;

	s->value-=1;

	if(s->value<0)	
		Wait(&s->waitingThreads);	
	  
	return 0;	
}

static int Sys_V(struct Interrupt_State* state)
{
		struct Kernel_Thread *kthread; 
		struct Semaphore *s=s_sphlist.head;
		
		while(s!=0)
		{
			if(s->semaphoreID==state->ebx)	
				 break;			
			s=Get_Next_In_Semaphore_List(s);				
		}  
	if(s==0)
		return -1;

	s->value+=1;

	if(s->value>=0){
		kthread = s->waitingThreads.head;
		if( kthread !=0){
			//kthread = Get_Front_Of_Thread_Queue(&s->waitingThreads);
			//Remove_Thread(&s->waitingThreads, kthread);	
			Wake_Up_One(&s->waitingThreads);
		}
	}
	  
	  return 0;		
}
```

###	运行结果
多级调度队列实现，如图3-13和3-14所示，从结果来看这两种调度算法在运行过程中，每个相同的时间间输出的2或者1基本相等。
 
图 3 13

 
图 3 14
信号量测试，如图3-15和3-16所示，结果显示已经成功的实现了信号量的创建以及销毁，以及使用信号量实现单个共享资源的生产消费问题。
 
图 3 15
 
图 3 16
#	课程设计过程中问题
问题1：在project1中运行a.exe文件的时候没有正确的把代码中的两个字符串打印出来，只打印出了一个全局变量的字符串。
解决方法：因为是局部变量和全局变量的地址段不一样，所以把不能正常输出的字符串改成全局变量或者设为静态变量即可解决。
问题2：在make depend 和make生成文件过程中出现Permission denied，显示权限不够，不允许生成文件。
解决方法：可能是由于使用root权限修改文件夹，导致权限级别变高，不允许普通用户权限生成文件，在指令前加sudo使用root权限运行即可。
问题3：在project3中对于多级调度算法以及时间片轮转算法一直不能准确的理解。
解决方法：使用source inside等代码阅读软件对代码函数以及头文件进行追踪阅读理解，慢慢的体验到进程创建，销毁，运行，调度的美妙。
#	总结
在本次课程设计中，实现了project0，1，2，3。发现了几个project的项目设计都是有很大的关联性的，在项目0中实现了从键盘读取字符串，理解了操作系统是怎么实现输入的，还有格式化的输出，还有理解了操作系统中最重要的中断操作。在项目二中，通过读取exe文件并分析其中的elf文件，并使用其中的代码段创建进程，从中理解到操作系统如何通过一个可执行文件，从中读取信息并默认生成一个内核进程。而项目三则在项目二基础上进一步把进程创建这个操作分离为用户进程和内核进程。并提供了系统调用来实现在用户进程进行中断进入内核创建用户进程。在项目三则在项目二上的原始先进先出进程调度算法扩展为可以在多级队列调度算法和时间片轮转算法间切换。还有同时实现了信号量，有效解决了生产消费问题。
通过这次课程设计深刻的理解到了操作系统如何管理与配置内存、决定系统资源供需的优先次序、控制输入与输出设备。巩固了操作系统理论学习的概念、原理、设计、算法及数据结构。阅读代码过程中感受到了操作系统从无到有的发展不易，还有操作系统深层次的对硬件资源的管理，而不仅仅限于停留于现在成熟的操作系统的炫酷的界面展示。
#更详细的解析参考csdn另一个博主 本然233
#附录
Project2全部代码

```
intSpawn(const.char*program,const.char*command,struct.Kernel_Thread**pThread)
{
Int rc;
//标记各函数的返回值，为0则表示成功，否则失败
char*exeFileData=0;
//保存在内存缓冲中的用户程序可执行文件ulong_t exeFileLength;
//可执行文件的长度
Struct User_Context*userContext=0;
//指向User_Conetxt的指针
Struct Kernel_Thread*process=0;
//指向Kernel_Thread*pThread的指针
Struct Exe_Format exeFormat;
//调用Parse_ELF_Executable函数得到的可执行文件信息
if((rc=Read_Fully(program,(void**)&exeFileData,&exeFileLength)) !=0){//调用Read_Fully函数将名为program的可执行文件全部读入内存缓冲区Print("Failed to Read File%s!\n",program);goto fail;}
if((rc=Parse_ELF_Executable(exeFileData,exeFileLength,&exeFormat))!=0){//调用Parse_ELF_Executable函数分析ELF格式文件Print("Failed to Parse ELF File!\n");goto fail;}
if((rc=Load_User_Program(exeFileData,exeFileLength,&exeFormat,command,&userContext))!=0)
{//调用Load_User_Program将可执行程序的程序段和数据段装入内存Print("Failed to Load User Program!\n");goto fail;}
//在堆分配方式下释放内存并再次初始化exeFileData Free(exeFileData);exeFileData=0;
/* 开始用户进程,调用Start_User_Thread函数创建一个进程并使其进入准备运行队列*/
process=Start_User_Thread(userContext,false);
if(process!=0){//不是核心级进程(即为用户级进程)KASSERT(process->refCount==2);/*返回核心进程的指针*/*pThread=process;
rc=process->pid;//记录当前进程的ID} else//超出内存 project2\include\geekos\errno.h    rc = ENOMEM;   return rc; 
fail: //如果新进程创建失败则注销User_Context对象   if (exeFileData != 0) 
   Free(exeFileData);//释放内存   if (userContext != 0) 
   Destroy_User_Context(userContext);//销毁进程对象   return rc; } 
------------------------------------- //切换至用户上下文  
void Switch_To_User_Context(struct Kernel_Thread* kthread, struct Interrupt_State* state) { 
static struct User_Context* s_currentUserContext; /* last user context used */  //extern int userDebug; 
 struct User_Context* userContext = kthread->userContext;//指向User_Conetxt的指针，并初始化为准备切换的进程  KASSERT(!Interrupts_Enabled()); 
 if (userContext == 0) { //userContext为0表示此进程为核心态进程就不用切换地址空间   return;   } 
 if (userContext != s_currentUserContext) {   ulong_t esp0; 
  //if (userDebug) Print("A[%p]\n", kthread); 
 
 Switch_To_Address_Space(userContext);
esp0 = ((ulong_t) kthread->stackPage) + PAGE_SIZE;   //if (userDebug) 
  // Print("S[%lx]\n", esp0); /* 新进程的核心栈. */ 
  Set_Kernel_Stack_Pointer(esp0);//设置内核堆栈指针 /* New user context is active */ 
  s_currentUserContext = userContext;   } }  
static struct User_Context* Create_User_Context(ulong_t size) {struct User_Context * UserContext;     size = Round_Up_To_Page(size); 
UserContext = (struct User_Context *)Malloc(sizeof(struct User_Context));//为用户态进程     if (UserContext != 0) 
 UserContext->memory = Malloc(size);   
  //为核心态进程     
else 
goto fail;//内存为空 
if (0 == UserContext->memory)
  goto fail;   
memset(UserContext->memory, '\0', size);UserContext->size = size;
    UserContext->ldtDescriptor = Allocate_Segment_Descriptor();if (0 == UserContext->ldtDescriptor)goto fail;
Init_LDT_Descriptor(UserContext->ldtDescriptor, UserContext->ldt, NUM_USER_LDT_ENTRIES);   
  UserContext->ldtSelector = Selector(KERNEL_PRIVILEGE, true, Get_Descriptor_Index(UserContext->ldtDescriptor));
   Init_Code_Segment_Descriptor(&UserContext->ldt[0],
(ulong_t) UserContext->memory,size / PAGE_SIZE,USER_PRIVILEGE);
//新建一个数据段 
Init_Data_Segment_Descriptor(&UserContext->ldt[1], 
(ulong_t) UserContext->memory,size / PAGE_SIZE,USER_PRIVILEGE); 
//新建数据段和文本段选择子 
UserContext->csSelector = Selector(USER_PRIVILEGE, false, 0);   UserContext->dsSelector = Selector(USER_PRIVILEGE, false, 1);//将引用数清0 
    UserContext->refCount = 0;return UserContext; fail: 
    if (UserContext != 0){ 
if (UserContext->memory != 0){Free(UserContext->memory);        } 
Free(UserContext);}
return 0;}
 //摧毁用户上下文 
void Destroy_User_Context(struct User_Context* userContext) 
 
{Free_Segment_Descriptor(userContext->ldtDescriptor);     userContext->ldtDescriptor=0;   
Free(userContext->memory);  
  userContext->memory=0;   
   Free(userContext);     userContext=0; } 
int Load_User_Program(char *exeFileData, ulong_t exeFileLength,struct Exe_Format *exeFormat, const char *command, 
    struct User_Context **pUserContext) 
{int i; 
 ulong_t maxva = 0;//要分配的最大内存空间  
unsigned numArgs;//进程数目 
 ulong_t argBlockSize;//参数块的大小 
ulong_t size,
argBlockAddr; s
truct User_Context *userContext = 0;   
for (i = 0; i < exeFormat->numSegments; ++i)
 {   
  struct Exe_Segment *segment = &exeFormat->segmentList[i]; 
  ulong_t topva = segment->startAddress + segment->sizeInMemory; /* FIXME: range check */ 
  if (topva > maxva)    maxva = topva;   } 
 Get_Argument_Block_Size(command, &numArgs, &argBlockSize);//获取参数块信息 
 size = Round_Up_To_Page(maxva) + DEFAULT_USER_STACK_SIZE;//用户进程大小=参数块总大小 + 进程堆栈大小(8192)  argBlockAddr = size;  size += argBlockSize; 
 userContext = Create_User_Context(size);//按相应大小创建一个进程  if (userContext == 0)//如果为核心态进程   return -1; 
 for (i = 0; i < exeFormat->numSegments; ++i) { 
struct Exe_Segment *segment = &exeFormat->segmentList[i]; 
  //根据段信息将用户程序中的各段内容复制到分配的用户内存空间 
  memcpy(userContext->memory + segment->startAddress, exeFileData + segment->offsetInFile,segment->lengthInFile);   } 
 //格式化参数块 
 Format_Argument_Block(userContext->memory + argBlockAddr, numArgs, argBlockAddr, command); 
 //初始化数据段，堆栈段及代码段信息 
 userContext->entryAddr = exeFormat->entryAddr;  userContext->argBlockAddr = argBlockAddr;  userContext->stackPointerAddr = argBlockAddr; 
 //将初始化完毕的User_Context赋给*pUserContext  *pUserContext = userContext;  return 0;//成功 } 
bool Copy_From_User(void* destInKernel, ulong_t srcInUser, ulong_t bufSize) {     struct User_Context * UserContext = g_currentThread->userContext;  //--: check if memory if validated 
 if (!Validate_User_Memory(UserContext,srcInUser, bufSize))   return false;  //--:user->kernel 
 memcpy(destInKernel, UserContext->memory + srcInUser, bufSize);      return true; } 
----------------------------------------- //将内核态的进程复制到用户态 
bool Copy_To_User(ulong_t destInUser, void* srcInKernel, ulong_t bufSize) {struct User_Context * UserContext = g_currentThread->userContext;  //--: check if memory if validated 
 if (!Validate_User_Memory(UserContext, destInUser,  bufSize))   return false;   
 //--:kernel->user 
 memcpy(UserContext->memory + destInUser, srcInKernel, bufSize);  return true; } 
---------------------------------------- //切换到用户地址空间 
void Switch_To_Address_Space(struct User_Context *userContext)
{ 
 ushort_t ldtSelector= userContext->ldtSelector;/* Switch to the LDT of the new user context */ 
 __asm__ __volatile__ ("lldt %0"::"a"(ldtSelector)); }   
#include <geekos/user.h>  //创建一个用户进程 
/*static*/ void Setup_User_Thread(struct Kernel_Thread* kthread, struct User_Context* userContext) 
{ulong_t eflags = EFLAGS_IF; 
unsigned csSelector=userContext->csSelector;
 unsigned dsSelector=userContext->dsSelector;
 Attach_User_Context(kthread, userContext); 
    Push(kthread, dsSelector);                       
     Push(kthread, userContext->stackPointerAddr);  
  Push(kthread, eflags);                        //Eflags 
    Push(kthread, csSelector);
Push(kthread, userContext->entryAddr); 
  Push(kthread, 0);  
   Push(kthread, 0); //中断号(0)   
//初始化通用寄存单元，将ESI用户传递参数块地址Push(kthread, 0); /* eax */     Push(kthread, 0); /* ebx */     Push(kthread, 0); /* edx */     Push(kthread, 0); /* edx */ 
    Push(kthread, userContext->argBlockAddr); /* esi */     Push(kthread, 0); /* edi */     Push(kthread, 0); /* ebp */   
    //初始化数据段寄存单元 
    Push(kthread, dsSelector); /* ds */     Push(kthread, dsSelector); /* es */     Push(kthread, dsSelector); /* fs */     Push(kthread, dsSelector); /* gs */ }   
//开始用户进程
struct Kernel_Thread* Start_User_Thread(struct User_Context* userContext, bool detached) 
{ struct Kernel_Thread* kthread = Create_Thread(PRIORITY_USER, detached);  //为用户态进程  if (kthread != 0){ 
  Setup_User_Thread(kthread,userContext);   Make_Runnable_Atomic(kthread);  } 
 return kthread; }   
//需在此文件别的函数前增加一个函数，函数名为Copy_User_String，它被函数Sys_PrintString调用，具体实现如下： 
static int Copy_User_String(ulong_t uaddr, ulong_t len, ulong_t maxLen, char **pStr) {   int rc = 0;     char *str; 
    if (len > maxLen){    //超过最大长度        return EINVALID;     } 
    str = (char*) Malloc(len+1);    //为字符串分配空间     if (0 == str){ 
       rc = ENOMEM;        goto fail;     } 
    if (!Copy_From_User(str, uaddr, len)){    //从用户空间中复制数据        rc = EINVALID;        Free(str);        goto fail;     } 
    str[len] = '\0';     //成功     *pStr = str; fail: 
    return rc; } 
----------------------------------------- 
static int Sys_Exit(struct Interrupt_State* state) { Exit(state->ebx); } 
----------------------------------------- 
static int Sys_PrintString(struct Interrupt_State* state)
 
{int rc = 0;//返回值 
 uint_t length = state->ecx;//字符串长度  uchar_t* buf = 0;  if (length > 0) { 
/* Copy string into kernel. 将字符串复制到内核*/ 
  if ((rc = Copy_User_String(state->ebx, length, 1023, (char**) &buf)) != 0)    goto done; 
/* Write to console. 将字符串打印到屏幕 */   Put_Buf(buf, length);   } done: 
  if (buf != 0)    Free(buf);   return rc; } 
---------------------------------------------- 
static int Sys_GetKey(struct Interrupt_State* state) {
 return Wait_For_Key(); //返回按键码keyboard.c/Wait_For_Key() } 
--------------------------------------------- 
static int Sys_SetAttr(struct Interrupt_State* state) {    Set_Current_Attr((uchar_t) state->ebx);  return 0; } 
--------------------------------------------- 
static int Sys_GetCursor(struct Interrupt_State* state) {int row, col; 
 Get_Cursor(&row, &col); 
 if (!Copy_To_User(state->ebx, &row, sizeof(int)) ||!Copy_To_User(state->ecx, &col, sizeof(int)))   return -1;  return 0; } 
----------------------------------------------- 
static int Sys_PutCursor(struct Interrupt_State* state) 
{ return Put_Cursor(state->ebx, state->ecx) ? 0 : -1; } 
----------------------------------------------- 
static int Sys_Spawn(struct Interrupt_State* state)
{    int rc;         
char *command = 0; 
//用户命令  
struct Kernel_Thread *process; 
/* Copy program name and command from user space. */ 
 if ((rc = Copy_User_String(state->ebx, state->ecx, VFS_MAX_PATH_LEN, &program)) != 0) 
 {//从用户空间复制进程名称   
goto fail;  } 
 if(rc = Copy_User_String(state->edx, state->esi, 1023, &command)) != 0)  {//从用户空间复制用户命令   goto fail;  } 
 Enable_Interrupts();  //开中断 
 rc = Spawn(program, command, &process);//得到进程名称和用户命令后便可生成一个新进程 
 if (rc == 0) {//若成功则返回新进程ID号   KASSERT(process != 0);rc = process->pid;  } 
 Disable_Interrupts();//关中断 fail://返回小于0的错误代码if (program != 0)Free(program);if (command != 0)Free(command);  return rc; } 
----------------------------------------- 
static int Sys_Wait(struct Interrupt_State* state) {int exitCode; 
struct Kernel_Thread *kthread = Lookup_Thread(state->ebx);  
if (kthread == 0)   return -1; 
Enable_Interrupts();  exitCode = Join(kthread);  Disable_Interrupts();  return exitCode; } 
--------------------------------------- 
static int Sys_GetPID(struct Interrupt_State* state)
{return g_currentThread->pid;}
=================main.c================== Spawn_Init_Process(void){
struct.Kernel_Thread*pThread;
Spawn("/c/shell.exe","/c/shell.exe",&pThread);}
```

<!--stackedit_data:
eyJoaXN0b3J5IjpbMTYxMjIzODE2MiwtMzM0MjEwNTY4XX0=
-->