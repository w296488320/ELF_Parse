package com.makelove.soAnalyze.bean;

import com.makelove.soAnalyze.LogUtils;
import com.makelove.soAnalyze.Utils;

import java.util.ArrayList;

/**
 * 	LinkingView （观看的视图 ida观看）
 	ExecutionView（执行的视图）

	 在执行的时候 会将标识相同的Section 合成到
	 Segment里面 增加执行速度
 */
public class ElfType32 {
	
	public elf32_rel rel;
	public elf32_rela rela;

	public ArrayList<Elf32_Sym> symList = new ArrayList<Elf32_Sym>();



	//elf头部信息
	public Elf32_Header hdr;

	/**
	 * 多个Program 具体
	 * 存储so 的链接用信息，主要是用于给外部程序详细地提供本so
	 * 的信息，比如第几行对应哪个函数，什么名字，
	 * 对应着源码神马位置等等。Ida
	 * 则是通过读取该头信息进行so分析的。
	 */
	public ArrayList<Elf32_ProgramHeeaderItem> ProgramHeaderList = new ArrayList<Elf32_ProgramHeeaderItem>();


	/**
	 * 多个Section 具体
	 * 存储so 文件运行时候需要的信息。
		该信息会直接地被linker 所使用，运用于so 加载上。
		因此这个header 的数据是肯定可信的。

	 	常用 数据段 包括
	 1，代码段 （.text.）程序编译后的指令
	 2，只读数据段，（rodata）只读数据，通常是程序里面的 只读变量 和 字符串 常量
	 3，数据段（.data）初始化了 全局的 静态变量 和 局部 静态 变量
	 4，BSS段，未初始化的 全局变量 和 局部 静态 变量
	 	不常用
	 */
	public ArrayList<Elf32_SectionHeaderItem> SectionHeaderList = new ArrayList<Elf32_SectionHeaderItem>();
	//可能会有多个字符串值
	public ArrayList<elf32_strtb> strtbList = new ArrayList<elf32_strtb>();



	
	public ElfType32() {
		rel = new elf32_rel();
		rela = new elf32_rela();
		hdr = new Elf32_Header();
	}
	
	/**
	 *  typedef struct elf32_rel {
		  Elf32_Addr	r_offset;
		  Elf32_Word	r_info;
		} Elf32_Rel;
	 *
	 */
	public class elf32_rel {
		public byte[] r_offset = new byte[4];
		public byte[] r_info = new byte[4];
		
		@Override
		public String toString(){
			return "r_offset:"+Utils.bytes2HexString(r_offset)+";r_info:"+ Utils.bytes2HexString(r_info);
		}
	}
	
	/**
	 *  typedef struct elf32_rela{
		  Elf32_Addr	r_offset;
		  Elf32_Word	r_info;
		  Elf32_Sword	r_addend;
		} Elf32_Rela;
	 */
	public class elf32_rela{
		public byte[] r_offset = new byte[4];
		public byte[] r_info = new byte[4];
		public byte[] r_addend = new byte[4];
		
		@Override
		public String toString(){
			return "r_offset:"+Utils.bytes2HexString(r_offset)+";r_info:"+Utils.bytes2HexString(r_info)+";r_addend:"+Utils.bytes2HexString(r_info);
		}
	}
	
	/**
	 * typedef struct elf32_sym{
		  Elf32_Word	st_name;
		  Elf32_Addr	st_value;
		  Elf32_Word	st_size;
		  unsigned char	st_info;
		  unsigned char	st_other;
		  Elf32_Half	st_shndx;
		} Elf32_Sym;
	 */
	public static class Elf32_Sym{
		public byte[] st_name = new byte[4];
		public byte[] st_value = new byte[4];
		public byte[] st_size = new byte[4];
		public byte st_info;
		public byte st_other;
		public byte[] st_shndx = new byte[2];
		
		@Override
		public String toString(){
			return "st_name:"+Utils.bytes2HexString(st_name)
					+"\nst_value:"+Utils.bytes2HexString(st_value)
					+"\nst_size:"+Utils.bytes2HexString(st_size)
					+"\nst_info:"+(st_info/16)
					+"\nst_other:"+(((short)st_other) & 0xF)
					+"\nst_shndx:"+Utils.bytes2HexString(st_shndx);
		}
	}
	
	public void printSymList(){
		for(int i=0;i<symList.size();i++){
			LogUtils.e("The "+(i+1)+" Symbol Table:");
			LogUtils.e(symList.get(i).toString());
		}
	}

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
	/**
	 * 这里需要注意的是还需要做一次转化
	 *  #define ELF_ST_BIND(x)	((x) >> 4)
	 	#define ELF_ST_TYPE(x)	(((unsigned int) x) & 0xf)
	 */
	/**
	 * 32为 ELF Header
	 */
	public class Elf32_Header {

		/**
		 *	ElF标识信息
		 */
		public byte[] e_ident = new byte[16];
		/**
		 * 	类型
		 * .dynsym的类型为DYNSYM表示该节区包含了要动态链接的符号等等
		 */
		public byte[] e_type = new byte[2];

		/**
		 * 目标体系结构类型 如 EM_ARM (40)
		 */
		public byte[] e_machine = new byte[2];

		/**
		 * 目标文件版本
		 * 如EV_CURRENT (1)
		 */
		public byte[] e_version = new byte[4];

		/**
		 * 程序入口的虚拟地址，如果没有则为0
		 */
		public byte[] e_entry = new byte[4];
		/**
		 * 程序头部表偏移
		 * Program_header 地址
		 * 头一般大小为 34H 十进制 是 52
		 *
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
		 *
		 */
		public byte[] e_ehsize = new byte[2];
		/**
		 *	程序头部表格的表项大小，2个字节
		 *	Program_header 里面每一个Item大小
		 *	20H   	32个字节
		 */
		public byte[] e_phentsize = new byte[2];
		/**
		 * 	Program_header Item的 个数
		 *
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
		 *
		 * 描述程序中包含可执行程序代码的部分
		 * 这些代码将在加载时映射到程序地址空间。
		 *
		 * Section header 字符串的 位置
		 * 程序 执行的 Sectionheader 字符串开始的 位置
		 */
		public byte[] e_shstrndx = new byte[2];
		
		@Override
		public String toString(){
			return  "magic:"+ Utils.bytes2HexString(e_ident) 
					+"\ne_type:"+Utils.bytes2HexString(e_type)
					+"\ne_machine:"+Utils.bytes2HexString(e_machine)
					+"\ne_version:"+Utils.bytes2HexString(e_version)
					+"\ne_entry:"+Utils.bytes2HexString(e_entry)
					+"\nProgram_header_off:"+Utils.bytes2HexString(Program_header_off)
					+"\nSection_header_off:"+Utils.bytes2HexString(Section_header_off)
					+"\ne_flags:"+Utils.bytes2HexString(e_flags)
					+"\ne_ehsize:"+Utils.bytes2HexString(e_ehsize)
					+"\ne_phentsize:"+Utils.bytes2HexString(e_phentsize)
					+"\ne_phnumCount:"+Utils.bytes2HexString(e_phnumCount)
					+"\ne_shentsize:"+Utils.bytes2HexString(e_shentsize)
					+"\ne_shnumCount:"+Utils.bytes2HexString(e_shnumCount)
					+"\ne_shstrndx:"+Utils.bytes2HexString(e_shstrndx);
		}
	}
	
	/**
	 * Program_header 具体数据
	 * IDA  根据这个 解析 so
	 *
	 * 描述 一个 Segment的信息 (段)
	 * 在执行的时候 节会 根据 类型 凑成相同的段
	 *
	 * 段就是 映射关系 映射 真正 数据的信息
	 * IDA对这个 进行 分析  处理数据
	 */
	public static class Elf32_ProgramHeeaderItem {
		/**
		 *  描述段的类型
		 *	Segment type
		 */
		public byte[] p_type = new byte[4];
		/**
		 *	段偏移
		 *	这个 Segment 开始的 位置
		 */
		public byte[] p_offset = new byte[4];

		/**
		 * 虚拟地址
		 * 所在程序段开始地址
		 */
		public byte[] p_vaddr = new byte[4];

		/**
		 * 段物理地址
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
		 * 在内存中的大小
		 */
		public byte[] p_memsz = new byte[4];
		/**
		 * 段相关标识
		 */
		public byte[] p_flags = new byte[4];

		/**
		 * 对齐取值
		 */
		public byte[] p_align = new byte[4];
		
		@Override
		public String toString(){
			return "p_type:"+ Utils.bytes2HexString(p_type)
					+"\np_offset:"+Utils.bytes2HexString(p_offset)
					+"\np_vaddr:"+Utils.bytes2HexString(p_vaddr)
					+"\np_paddr:"+Utils.bytes2HexString(p_paddr)
					+"\np_filesz:"+Utils.bytes2HexString(p_filesz)
					+"\np_memsz:"+Utils.bytes2HexString(p_memsz)
					+"\np_flags:"+Utils.bytes2HexString(p_flags)
					+"\np_align:"+Utils.bytes2HexString(p_align);
		}
	}
	
	public void printPhdrList(){
		for(int i = 0; i< ProgramHeaderList.size(); i++){
			LogUtils.e("The "+(i+1)+" Program Header:");
			LogUtils.e(ProgramHeaderList.get(i).toString());
		}
	}
	
	/**
	 * typedef struct Elf32_SectionHeaderItem {
		  Elf32_Word	sh_name;
		  Elf32_Word	sh_type;
		  Elf32_Word	sh_flags;
		  Elf32_Addr	sh_addr;
		  Elf32_Off	sh_offset;
		  Elf32_Word	sh_size;
		  Elf32_Word	sh_link;
		  Elf32_Word	sh_info;
		  Elf32_Word	sh_addralign;
		  Elf32_Word	sh_entsize;
		} Elf32_Shdr;
	 */
	public static class Elf32_SectionHeaderItem {

		/**
		 * 节区名称，是字符串表节区索引
		 */
		public byte[] sh_name = new byte[4];

		/**
		 * 节区类型
		 */
		public byte[] sh_type = new byte[4];
		/**
		 * 节区标志
		 */
		public byte[] sh_flags = new byte[4];


		/**
		 * 节区内存地址
		 */
		public byte[] sh_addr = new byte[4];
		/**
		 * 节区偏移
		 */
		public byte[] sh_offset = new byte[4];
		/**
		 * 节区长度
		 */
		public byte[] sh_size = new byte[4];
		/**
		 * 节区头部表索引链接
		 */
		public byte[] sh_link = new byte[4];
		/**
		 * 附加信息
		 */
		public byte[] sh_info = new byte[4];
		/**
		 * 对齐约束
		 */
		public byte[] sh_addralign = new byte[4];
		/**
		 * 节区表项大小
		 */
		public byte[] sh_entsize = new byte[4];
		
		@Override
		public String toString(){
			return "sh_name:"+Utils.bytes2HexString(sh_name)/*Utils.byte2Int(sh_name)*/
					+"\nsh_type:"+Utils.bytes2HexString(sh_type)
					+"\nsh_flags:"+Utils.bytes2HexString(sh_flags)
					+"\nsh_add:"+Utils.bytes2HexString(sh_addr)
					+"\nsh_offset:"+Utils.bytes2HexString(sh_offset)
					+"\nsh_size:"+Utils.bytes2HexString(sh_size)
					+"\nsh_link:"+Utils.bytes2HexString(sh_link)
					+"\nsh_info:"+Utils.bytes2HexString(sh_info)
					+"\nsh_addralign:"+Utils.bytes2HexString(sh_addralign)
					+"\nsh_entsize:"+ Utils.bytes2HexString(sh_entsize);
		}
	}
	
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
	
	public void printShdrList(){
		for(int i = 0; i< SectionHeaderList.size(); i++){
			LogUtils.e("The "+(i+1)+" Section Header:");
			LogUtils.e(SectionHeaderList.get(i).toString());
		}
	}
	
	
	public static class elf32_strtb{
		public byte[] str_name;
		public int len;
		
		@Override
		public String toString(){
			return "str_name:"+str_name
					+"len:"+len;
		}
	}
}
