package com.makelove.soAnalyze.bean;

import com.makelove.soAnalyze.LogUtils;
import com.makelove.soAnalyze.Utils;

import java.util.ArrayList;

/**
 * LinkingView （观看的视图 ida观看）
 * ExecutionView（执行的视图）
 * <p>
 * 在执行的时候 会将标识相同的Section 合成到
 * Segment里面 增加执行速度
 * <p>
 * <p>
 * Elf32_Addr 4 无符号程序地址
 * Elf32_Half 2 无符号中等整数
 * Elf32_Off 4 无符号文件偏移
 * Elf32_SWord 4 有符号大整数
 * Elf32_Word 4 无符号大整数
 * unsigned char 1 无符号笑整数
 * <p>
 * ELF文件  装载流程
 * 开始 -》
 * 读取前52个字节 解析 文件头-》
 * 定位到程序头（program header）（每一个 都是 segment） 并解析（映射） -》
 * 获取LOAD类型的 segment -》
 * 将其映射到内存空间 -》
 * MemSize>FileSize?大于的部分填充0:跳转到 Entry point -》
 * 结束
 *
 * 常用节区介绍
 代码段
 代码段就是存放指令的节区(.text),符号表中的 st_value
 指向代码段中具体的函数地址,以其地址的指令为函数开头。
 过程链接表
 .plt节区,其每个表项都是一段代码,作用是跳转至真实的函数地址
 哈希表
 .hash节区。哈希表的结构
 其中nchain为符号表表项数,nchain 和 nbucket 是 chain 和 bucket 的数量。
 数据段
 .data、.bss、.rodata都属于数据段。
 .data 存放已初始化的全局变量、常量。
 .bss 存放未初始化的全局变量,所以此段数据均为0，仅作占位。
 .rodata 是只读数据段,此段的数据不可修改,存放常量。

 .init_array .fini_array
 程序运行时,执行.init_array中的指令。
 程序退出时,执行.fini_array中的指令。
 */
public class ElfType32 {

    //Bind字段==》st_info
    public static final int STB_LOCAL = 0;
    public static final int STB_GLOBAL = 1;
    public static final int STB_WEAK = 2;
    //Type字段==》st_other
    public static final int STT_NOTYPE = 0;
    public static final int STT_OBJECT = 1;
    public static final int STT_FUNC = 2;
    public static final int STT_SECTION = 3;
    public static final int STT_FILE = 4;
    /****************sh_type********************/
    public static final int SHT_NULL = 0;
    public static final int SHT_PROGBITS = 1;
    public static final int SHT_SYMTAB = 2;
    public static final int SHT_STRTAB = 3;
    public static final int SHT_RELA = 4;
    public static final int SHT_HASH = 5;
    public static final int SHT_DYNAMIC = 6;
    public static final int SHT_NOTE = 7;
    public static final int SHT_NOBITS = 8;
    public static final int SHT_REL = 9;
    public static final int SHT_SHLIB = 10;
    public static final int SHT_DYNSYM = 11;
    /**
     * 这里需要注意的是还需要做一次转化
     *  #define ELF_ST_BIND(x)	((x) >> 4)
     #define ELF_ST_TYPE(x)	(((unsigned int) x) & 0xf)
     */
    public static final int SHT_NUM = 12;
    public static final int SHT_LOPROC = 0x70000000;
    public static final int SHT_HIPROC = 0x7fffffff;
    public static final int SHT_LOUSER = 0x80000000;
    public static final int SHT_HIUSER = 0xffffffff;
    public static final int SHT_MIPS_LIST = 0x70000000;
    public static final int SHT_MIPS_CONFLICT = 0x70000002;
    public static final int SHT_MIPS_GPTAB = 0x70000003;
    public static final int SHT_MIPS_UCODE = 0x70000004;
    /*****************sh_flag***********************/
    public static final int SHF_WRITE = 0x1;
    public static final int SHF_ALLOC = 0x2;
    public static final int SHF_EXECINSTR = 0x4;
    public static final int SHF_MASKPROC = 0xf0000000;
    public static final int SHF_MIPS_GPREL = 0x10000000;
    public elf32_rel rel;
    public elf32_rela rela;


    //符号表集合
    public ArrayList<Elf32_Sym> symList = new ArrayList<Elf32_Sym>();


    //elf头部信息
    public Elf32_Header hdr;
    /**
     * 多个Program 具体
     * 存储so 的链接用信息，主要是用于给外部程序详细地提供本so
     * 的信息，比如第几行对应哪个函数，什么名字，
     * 对应着源码神马位置等等。Ida
     * 则是通过读取该头信息进行so分析的。
     * <p>
     * 程序头 它描述了elf文件该如何被操作系统映射到内存空间中。
     * 程序 在 运行时候 将其加载到对应的内存   空间
     * 对于 memisiz大于 filesiz的 部分 全部 填充为 0
     * 加载完毕  以后让程序调转到 入口地址
     */
    public ArrayList<Elf32_ProgramHeeaderItem> ProgramHeaderList = new ArrayList<Elf32_ProgramHeeaderItem>();
    /**
     * 多个Section 具体
     * 存储so 文件运行时候需要的信息。
     * 该信息会直接地被linker 所使用，运用于so 加载上。
     * 因此这个header 的数据是肯定可信的。
     */
    public ArrayList<Elf32_SectionHeaderItem> SectionHeaderList = new ArrayList<Elf32_SectionHeaderItem>();
    //可能会有多个字符串值
    public ArrayList<elf32_strtb> strtbList = new ArrayList<elf32_strtb>();

    public ElfType32() {
        rel = new elf32_rel();
        rela = new elf32_rela();
        hdr = new Elf32_Header();
    }

    public void printSymList() {
        for (int i = 0; i < symList.size(); i++) {
            LogUtils.e("The " + (i + 1) + " Symbol Table:");
            LogUtils.e(symList.get(i).toString());
        }
    }

    public void printPhdrList() {
        for (int i = 0; i < ProgramHeaderList.size(); i++) {
            LogUtils.e("The " + (i + 1) + " Program Header:");
            LogUtils.e(ProgramHeaderList.get(i).toString());
        }
    }

    public void printShdrList() {
        for (int i = 0; i < SectionHeaderList.size(); i++) {
            LogUtils.e("The " + (i + 1) + " Section Header:");
            LogUtils.e(SectionHeaderList.get(i).toString());
        }
    }

    /**
     * 符号表
       符号: 指函数或者数据对象等。
     * typedef struct elf32_sym{
     * Elf32_Word	st_name;
     * Elf32_Addr	st_value;
     * Elf32_Word	st_size;
     * unsigned char	st_info;
     * unsigned char	st_other;
     * Elf32_Half	st_shndx;
     * } Elf32_Sym;
     */
    public static class Elf32_Sym {

        /**
         *  符号名称,给出的是一个在符号名称表(.dynstr)中的索引
         */
        public byte[] st_name = new byte[4];

        /**
         * 一般都是函数地址,或者是一个常量值
         */
        public byte[] st_value = new byte[4];

        /**
         *  st_value 地址开始,共占的长度大小
         */
        public byte[] st_size = new byte[4];
        /**
         *  用于标示此符号的属性,占一个字节(2个字)
         *  两个标示位,第一个标示位(低四位)标志作用域
         *  第二个标示位(高四位)标示符号类型
         */
        public byte st_info;
        /**
         * 固定值为0
         */
        public byte st_other;

        /**
         * 每个符号表项都以和其他节区间的关系的方式给出定义。
         * 此成员给出相关的节区头部表索引
         */
        public byte[] st_shndx = new byte[2];

        @Override
        public String toString() {
            return "st_name:" + Utils.bytes2HexString(st_name)
                    + "\nst_value:" + Utils.bytes2HexString(st_value)
                    + "\nst_size:" + Utils.bytes2HexString(st_size)
                    + "\nst_info:" + (st_info / 16)
                    + "\nst_other:" + (((short) st_other) & 0xF)
                    + "\nst_shndx:" + Utils.bytes2HexString(st_shndx);
        }
    }

    /**
     * Program_header 具体数据
     * IDA  根据这个 解析 so
     * <p>
     * Program header描述的是一个段在文件中的位置、
     * 大小以及它被放进内存后所在的位置和大小。
     * <p>
     * 描述 一个 Segment的信息 (段)
     * 在执行的时候 节会 根据 类型 凑成相同的段
     * <p>
     * 段就是 映射关系 映射 真正 数据的信息
     * IDA对这个 进行 分析  处理数据
     */
    public static class Elf32_ProgramHeeaderItem {
        /**
         * 描述段的类型（声明此段的作用类型）
         * Segment type
         * <p>
         * 00 PT_NULL 此数组元素未用。结构中其他成员都是未定义的。
         * 01 PT_LOAD 此数组元素给出一个可加载的段,段的大小由 p_filesz 和 p_memsz 描述。文件中的字节被映射到内存段开始处。如果 p_memsz 大于 p_filesz,“剩余”的字节要清零。p_filesz 不能大于 p_memsz。可加载的段在程序头部表格中根据 p_vaddr 成员按升序排列。
         * 02 PT_DYNAMIC 数组元素给出动态链接信息。
         * 03 PT_INTERP 数组元素给出一个 NULL 结尾的字符串的位置和长度,该字符串将被当作解释器调用。这种段类型仅对与可执行文件有意义(尽管也可能在共享目标文件上发生)。在一个文件中不能出现一次以上。如果存在这种类型的段,它必须在所有可加载段项目的前面。
         * 04 PT_NOTE 此数组元素给出附加信息的位置和大小。
         * 05 PT_SHLIB 此段类型被保留,不过语义未指定。包含这种类型的段的程序与 ABI不符。
         * 06 PT_PHDR 此类型的数组元素如果存在,则给出了程序头部表自身的大小和位置,既包括在文件中也包括在内存中的信息。此类型的段在文件中不能出现一次以上。并且只有程序头部表是程序的内存映像的一部分时才起作用。如果存在此类型段,则必须在所有可加载段项目的前面。
         * 0x70000000 PT_LOPROC 此范围的类型保留给处理器专用语义。
         * 0x7fffffff PT_HIPROC 此范围的类型保留给处理器专用语义。
         * 还有一些编译器或者处理器标识的段类型,有待补充。
         */
        public byte[] p_type = new byte[4];
        /**
         * 段偏移
         * 这个 Segment 开始的 位置
         * 当前所在程序段（Segment）开始地址
         * 段相对于（文件）的索引地址 也叫偏移地址
         */
        public byte[] p_offset = new byte[4];

        /**
         * 虚拟地址
         * 段在（内存）中的虚拟地址
         */
        public byte[] p_vaddr = new byte[4];

        /**
         * 段物理地址
         * 绝对地址
         */
        public byte[] p_paddr = new byte[4];
        /**
         * 段的文件映像大小
         * (在文件中的大小)
         * 因为有地址对齐 所以导致
         * 在文件中大小和 在内存中的大小不同
         */
        public byte[] p_filesz = new byte[4];

        /**
         * 在内存中的大小（长度）
         */
        public byte[] p_memsz = new byte[4];
        /**
         * 段相关标识(read、write、exec)
         * 可读 可写 可执行
         */
        public byte[] p_flags = new byte[4];

        /**
         * 对齐取值
         * 字节对其,p_vaddr 和 p_offset 对 p_align 取模后应该相等。
         */
        public byte[] p_align = new byte[4];

        @Override
        public String toString() {
            return "p_type:" + Utils.bytes2HexString(p_type)
                    + "\np_offset:" + Utils.bytes2HexString(p_offset)
                    + "\np_vaddr:" + Utils.bytes2HexString(p_vaddr)
                    + "\np_paddr:" + Utils.bytes2HexString(p_paddr)
                    + "\np_filesz:" + Utils.bytes2HexString(p_filesz)
                    + "\np_memsz:" + Utils.bytes2HexString(p_memsz)
                    + "\np_flags:" + Utils.bytes2HexString(p_flags)
                    + "\np_align:" + Utils.bytes2HexString(p_align);
        }
    }

    /**
     * Section Header Table 表项结构定义：
     * typedef struct Elf32_SectionHeaderItem {
     * Elf32_Word	sh_name;
     * Elf32_Word	sh_type;
     * Elf32_Word	sh_flags;
     * Elf32_Addr	sh_addr;
     * Elf32_Off	sh_offset;
     * Elf32_Word	sh_size;
     * Elf32_Word	sh_link;
     * Elf32_Word	sh_info;
     * Elf32_Word	sh_addralign;
     * Elf32_Word	sh_entsize;
     * } Elf32_Shdr;
     * 与Progarm Header类似,我们同样可以从ELF Header中得到
     * 索引地址(e_shoff)
     * 节区数量(e_shnum)
     * 表项大小(e_shentsize)
     * 还可以由名称节区索引(e_shstrndx)得到各节区的名称。
     * 在运行的时候 会将 多 section合成 segment
     *
     *  以“.”开头的节区名称是系统保留的。应用程序可以使用没有前缀的节区名称,以避免与系统节区冲突。
     *  目标文件中也可以包含多个名字相同的节区。
     *  保留给处理器体系结构的节区名称一般构成为:处理器体系结构名称简写 + 节区名称。
     *  处理器名称应该与 e_machine 中使用的名称相同。例如 .FOO.psect 街区是由 FOO 体系结构定义的 psect 节区。
     */
    public static class Elf32_SectionHeaderItem {

        /**
         * 常用 数据段 包括
         * 1，代码段 （.text.）程序编译后的指令
         * 2，只读数据段，（rodata）只读数据，通常是程序里面的 只读变量 和 字符串 常量
         * 3，数据段（.data）初始化了 全局的 静态变量 和 局部 静态 变量
         * 4，BSS段，未初始化的 全局变量 和 局部 静态 变量
         */
        public byte[] sh_name = new byte[4];

        /**
         * 节区类型
         * 节区,将来可能会取消这一限制。
         * SHT_NOTE
         * 7
         * 此节区包含以某种方式来标记文件的信息。
         * SHT_NOBITS
         * 8
         * 这种类型的节区不占用文件中的空间,其他方面和 SHT_PROGBITS 相似。尽管此节区不包含任何字节,成员sh_offset 中还是会包含概念性的文件偏移
         * SHT_REL
         * 9
         * 此节区包含重定位表项,其中没有补齐(addends),例如 32 位目标文件中的 Elf32_rel 类型。目标文件中可以拥有多个重定位节区。
         * SHT_SHLIB
         * 10
         * 此节区被保留,不过其语义是未规定的。包含此类型节区的程序与 ABI 不兼容。
         * SHT_DYNSYM
         * 11
         * 作为一个完整的符号表,它可能包含很多对动态链接而言不必要的符号。因此,目标文件也可以包含一个 SHT_DYNSYM 节区,其中保存动态链接符号的一个最小集合,以节省空间。
         * SHT_LOPROC
         * 0X70000000
         * 这一段(包括两个边界),是保留给处理器专用语义的。
         * SHT_HIPROC
         * 0X7FFFFFFF
         * 这一段(包括两个边界),是保留给处理器专用语义的。
         * SHT_LOUSER
         * 0X80000000
         * 此值给出保留给应用程序的索引下界。
         * SHT_HIUSER
         * 0X8FFFFFFF
         * 此值给出保留给应用程序的索引上界。
         */
        public byte[] sh_type = new byte[4];
        /**
         * 节区标志
         * 同Program Header的p_flags
         */
        public byte[] sh_flags = new byte[4];


        /**
         * 节区索引地址（和偏移地址一样 ）
         */
        public byte[] sh_addr = new byte[4];
        /**
         * 节区偏移
         * 节区相对于文件的偏移地址
         */
        public byte[] sh_offset = new byte[4];
        /**
         * 节区长度（大小）
         */
        public byte[] sh_size = new byte[4];
        /**
         * 节区头部表索引链接
         * 自己认为 就是 和当前节去有关系的 节
         * 根据010 得到 没有则为0
         */
        public byte[] sh_link = new byte[4];
        /**
         * 附加信息
         * 如果 sh_link 为 0 sh_info也为 0
         */
        public byte[] sh_info = new byte[4];
        /**
         * 对齐约束
         * 某些节区带有地址对齐约束。
         * 例如,如果一个节区保存一个doubleword,
         * 那么系统必须保证整个节区能够按双字对齐。
         * sh_addr 对sh_addralign 取模,
         * 结果必须为 0。目前仅允许取值为 0 和 2的幂次数。数值 0 和 1 表示节区没有对齐约束。
         */
        public byte[] sh_addralign = new byte[4];
        /**
         * 节区表项大小
         * 某些节区中包含固定大小的项目,如符号表。
         * 对于这类节区,此成员给出每个表项的长度字节数。
         * 如果节区中并不包含固定长度表项的表格,此成员取值为 0。
         */
        public byte[] sh_entsize = new byte[4];

        @Override
        public String toString() {
            return "sh_name:" + Utils.bytes2HexString(sh_name)/*Utils.byte2Int(sh_name)*/
                    + "\nsh_type:" + Utils.bytes2HexString(sh_type)
                    + "\nsh_flags:" + Utils.bytes2HexString(sh_flags)
                    + "\nsh_add:" + Utils.bytes2HexString(sh_addr)
                    + "\nsh_offset:" + Utils.bytes2HexString(sh_offset)
                    + "\nsh_size:" + Utils.bytes2HexString(sh_size)
                    + "\nsh_link:" + Utils.bytes2HexString(sh_link)
                    + "\nsh_info:" + Utils.bytes2HexString(sh_info)
                    + "\nsh_addralign:" + Utils.bytes2HexString(sh_addralign)
                    + "\nsh_entsize:" + Utils.bytes2HexString(sh_entsize);
        }
    }

    public static class elf32_strtb {
        public byte[] str_name;
        public int len;

        @Override
        public String toString() {
            return "str_name:" + str_name
                    + "len:" + len;
        }
    }

    /**
     * typedef struct elf32_rel {
     * Elf32_Addr	r_offset;
     * Elf32_Word	r_info;
     * } Elf32_Rel;
     */
    public class elf32_rel {
        public byte[] r_offset = new byte[4];
        public byte[] r_info = new byte[4];

        @Override
        public String toString() {
            return "r_offset:" + Utils.bytes2HexString(r_offset) + ";r_info:" + Utils.bytes2HexString(r_info);
        }
    }

    /**
     * typedef struct elf32_rela{
     * Elf32_Addr	r_offset;
     * Elf32_Word	r_info;
     * Elf32_Sword	r_addend;
     * } Elf32_Rela;
     */
    public class elf32_rela {
        public byte[] r_offset = new byte[4];
        public byte[] r_info = new byte[4];
        public byte[] r_addend = new byte[4];

        @Override
        public String toString() {
            return "r_offset:" + Utils.bytes2HexString(r_offset) + ";r_info:" + Utils.bytes2HexString(r_info) + ";r_addend:" + Utils.bytes2HexString(r_info);
        }
    }

    /**
     * 32为 ELF Header
     */
    public class Elf32_Header {

        /**
         * ElF标识信息
         */
        public byte[] e_ident = new byte[16];
        /**
         * 类型
         * .dynsym的类型为DYNSYM表示该节区包含了要动态链接的符号等等
         */
        public byte[] e_type = new byte[2];

        /**
         * 目标体系结构类型 如 EM_ARM (40)
         * EM_386  X86
         * EM_ARM  arm
         */
        public byte[] e_machine = new byte[2];

        /**
         * 目标文件版本
         * 如EV_CURRENT (1)
         */
        public byte[] e_version = new byte[4];

        /**
         * 程序入口的虚拟地址，如果没有则为0
         * 可执行程序入口点地址
         * 在 so被装载到内存里 会回到入口点
         */
        public byte[] e_entry = new byte[4];
        /**
         * 程序头部表偏移
         * Program_header 地址
         * 头一般大小为 34H 十进制 是 52
         */
        public byte[] Program_header_off = new byte[4];
        /**
         * 节区头部表偏移
         * Selection_header 地址
         */
        public byte[] Section_header_off = new byte[4];
        /**
         * 与文件相关，特定于处理器标志，4个字节
         * （没啥用 除了 ARM别的处理器的 标识 ）
         */
        public byte[] e_flags = new byte[4];
        /**
         * elf头部大小，2个字节
         */
        public byte[] e_ehsize = new byte[2];
        /**
         * 程序头部表格的表项大小，2个字节
         * Program_header 里面每一个Item大小
         * 20H   	32个字节
         */
        public byte[] e_phentsize = new byte[2];
        /**
         * Program_header Item的 个数
         */
        public byte[] e_phnumCount = new byte[2];

        /**
         * 节区头部表格的表项大小，2个字节
         * Selection_header 里面每一个Item大小
         * 28H 40
         */
        public byte[] e_shentsize = new byte[2];

        /**
         * Selection_header Item的 个数
         */
        public byte[] e_shnumCount = new byte[2];

        /**
         * 节区头部表格中与节区名称字符串表相关的表项索引
         * <p>
         * String Table Index,在节区表中有一个存储各节区名称的节区
         * (通常是最后一个),这里表示名称表在第几个节区。
         */
        public byte[] e_shstrndx = new byte[2];

        @Override
        public String toString() {
            return "magic:" + Utils.bytes2HexString(e_ident)
                    + "\ne_type:" + Utils.bytes2HexString(e_type)
                    + "\ne_machine:" + Utils.bytes2HexString(e_machine)
                    + "\ne_version:" + Utils.bytes2HexString(e_version)
                    + "\ne_entry:" + Utils.bytes2HexString(e_entry)
                    + "\nProgram_header_off:" + Utils.bytes2HexString(Program_header_off)
                    + "\nSection_header_off:" + Utils.bytes2HexString(Section_header_off)
                    + "\ne_flags:" + Utils.bytes2HexString(e_flags)
                    + "\ne_ehsize:" + Utils.bytes2HexString(e_ehsize)
                    + "\ne_phentsize:" + Utils.bytes2HexString(e_phentsize)
                    + "\ne_phnumCount:" + Utils.bytes2HexString(e_phnumCount)
                    + "\ne_shentsize:" + Utils.bytes2HexString(e_shentsize)
                    + "\ne_shnumCount:" + Utils.bytes2HexString(e_shnumCount)
                    + "\ne_shstrndx:" + Utils.bytes2HexString(e_shstrndx);
        }
    }
}
