
#include <jni.h>
#include <iostream>

#include<string.h>
#include<stdio.h>
#include "stdlib.h"
#include "elf.h"
#include "list"
#include<android/log.h>
#include <malloc.h>


using namespace std;
#define LOG_TAG "Q296488320"
//#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__) // 定义LOGD类型
//#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__) // 定义LOGI类型
//#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__) // 定义LOGW类型
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__) // 定义LOGE类型


//dynsym表 的偏移
int dynsym_off = 0;
//dynsym表 个数
int dynsym_size = 0;
//strtab表 偏移
int dynsym_str_off = 0;
//strtab表 个数
int dynsym_str_size = 0;
//dynsym 字符串信息的个数
int dynsym_entry_num = 0;

//Section 表 字符串的 开始 位置
int section_str_off = 0;
//Section 表 的大小
int section_str_size = 0;

//这个是保存 全部 dynstr表的 char *
char *symstr;

//这个是保存 全部 section表名字的 char *
char  * SectionTabStr;

void prepare(char *path);

bool checkELF(Elf32_Ehdr head);

void analyzeHead(Elf32_Ehdr head);

void analyzeProgram(FILE *pFILE);

void analyzeSection(FILE *pFILE);

void Test();

void initStringList(FILE *pFILE);

char *getSectionString(Elf32_Word name);

void fenge(char *str,char* SectionList[]);

void Main() {
    LOGE("Native Main被执行 ");
    // 一个 32位 ELF文件路径 可以根据 魔教第五个字节 01 32为 02 64位
    char *path = (char *) "/storage/emulated/0/So/main.so";
    prepare(path);
    return;
}

static Elf32_Ehdr elf_head;



//对于一个so库有两个符号表，
// 一个是“正常的”（在.symtab和.strtab节中）。
// 一个是动态的（.dynsym和.dynstr节中）
//dynstr的 类型 是 STRTAB
//dynsym 的类型 是 DYNSYM
//dynsym 也叫 动态符号表 用来保存与动态链接相关的导入导出符号，
// 不包括模块内部的符号。而 .symtab 则保存所有符号，包括 .dynsym 中的符号
//动态符号表中所包含的符号的符号名保存在动态符号字符串表 .dynstr 中。

//自己认为 就是 dynstr比 dynsym更广泛
//dynsym 只包含 函数名字 不包含 内部一些东西
// 而 dynstr全都包含 他俩之间互相关联
void prepare(char *path) {

    //创建个 ELF头


    FILE *fdr = fopen(path, "rb");


    if (fdr == NULL) {
        LOGE("Open file failed");
        return;
    }
    //elf_head=malloc(sizeof(Elf32_Ehdr));

    //将 数据 进行赋值
    //参数 1 elf文件的地址
    //参数 2 赋值的 个数
    //参数 3 读取的次数 比如 这个 输入流  可以 赋值几个 elf_head
    //参数 4 fopen拿到的 流
    //返回值 是 成功 有效读取 item的 个数
    size_t i = fread(&elf_head, 1, sizeof(Elf32_Ehdr), fdr);

    if (i != 0) {
        LOGE("READ OK %d ", i);
    } else {
        LOGE("READ ERROR  %d", i);
        return;
    }
    //检测ELF文件
    if (checkELF(elf_head)) {
        LOGE("是ELF文件 ");
        analyzeHead(elf_head);

        initStringList(fdr);

       // analyzeProgram(fdr);

        analyzeSection(fdr);
    } else {
        LOGE("不是ELF文件 ");
        fclose(fdr);
        return;
    }

    //不用的时候 需要将其关掉
    fclose(fdr);
    LOGE("执行完毕");
}




//list<Elf32_Sym *> DynsymList;

//list<Elf32_Sym *> DynstrList;

//Elf32_Sym *Section_str_array;


//主要是 通过 解析 ELF文件的符号表 dynsym进行 赋值



//兼容 c++
//extern "C"
void initStringList(FILE *pFILE) {

    LOGE("开始 解析 StringList");

    if (fseek(pFILE, (long) elf_head.e_shoff, SEEK_SET) != 0) {
        LOGE("StringList 移动到节头 失败");
        fclose(pFILE);
    } else {
        long i = ftell(pFILE);
        LOGE("StringList fseek成功 file当前位置 %d", i);
    }
    //首先遍历 section 集合 主要是 获取 dynsym 表
    // 和 dynstr表的 开始 位置和大小
    for (int i = 0; i < elf_head.e_shnum; i++) {
        Elf32_Shdr SItem;
        size_t PItem_size = fread(&SItem, 1, sizeof(Elf32_Shdr), pFILE);
        if (PItem_size != 0) {
            // LOGE("Section Item 匹配成功 总个数%d  当前的 Item %d", elf_head.e_phnum, i);
        } else {
            LOGE("Section Item  错误原因%d", PItem_size);
            return;
        }
        //初始化 字符串 表 方便后面打印名称使用
        //根据 010的值 对应 s_type是11  也就是 SHT_DYNSYM
        if (SItem.sh_type == SHT_DYNSYM) {
            dynsym_off = SItem.sh_offset;
            dynsym_size = SItem.sh_size;
        }

        if (SItem.sh_type == SHT_STRTAB) {
            // 如果是节名字符串表直接跳过
            // section表的 位置 判断 因为 shstrtab
            // （保存 section表的 名称的 表 ）表
            // 的类型也是 SHT_STRTAB
            if (i == elf_head.e_shstrndx) {
                LOGE("进来了");
                section_str_off = SItem.sh_offset;
                section_str_size = SItem.sh_size;



                //这个地方 需要 加 +1 因为在 010 可以得知 第一个 是 00
                if (fseek(pFILE, section_str_off + 1, SEEK_SET) != 0) {
                    LOGE("文件移动到 Section 表名字指针 失败 ");
                    fclose(pFILE);
                    return;
                } else {
                    LOGE("文件移动到 Section 表名字指针 成功 ");
                }

//                LOGE("当前 file偏移位置 %ld", ftell(pFILE));
//
//                LOGE("要分配的大小 %d", section_str_size);
//
                SectionTabStr = (char  *) malloc((size_t) (section_str_size + 1));
//
//                //LOGE("SectionTabStr 大小 %d", sizeof(*SectionTabStr));
//
                size_t str_size = fread(SectionTabStr, (size_t) section_str_size, 1, pFILE);



//                LOGE("888888888888  %s",SectionTabStr);
//
//                LOGE("888888888888  %s",SectionTabStr+10);

               // LOGE("888888888888  %s",SectionTabStr[1]);



                char *SectionList[elf_head.e_shnum];

                int count=0;
                for(int p=0;p<elf_head.e_shnum;p++) {
                    if (p == 0) {
                        SectionList[p] = SectionTabStr;
                    } else{
                        SectionList[p]=SectionTabStr+count;
                    }
                    LOGE("字符串 %s ",SectionList+count);
                    //LOGE("字符串 位置 %s"，&(*SectionList[p]));
                    count=count+strlen(SectionList[p]);

                }


                if (str_size != 0) {

                } else {
                    LOGE("字符串表 失败  ");
                    fclose(pFILE);
                    return;
                }
                if (SectionTabStr == NULL || strlen(SectionTabStr) == 0) {
                    LOGE("SectionTabStr   NULL ");
                    fclose(pFILE);
                    return;
                }
                LOGE("执行完毕");
                continue;
            }
            dynsym_str_off = SItem.sh_offset;
            dynsym_str_size = SItem.sh_size;
        }
    }
    LOGE("dynsym表 的 开始 位置 %d", dynsym_off);
    LOGE("dynsym表 的 整体大小  %d", dynsym_size);

    LOGE("dynstr表 的 开始 位置 %d", dynsym_str_off);
    LOGE("dynstr表 的 整体大小  %d", dynsym_str_size);


    //开始 遍历 dynstr表
    // 移动文件指针到符号表位置 dynstr表
    if (fseek(pFILE, dynsym_str_off, SEEK_SET) != 0) {
        LOGE("文件移动到 dynstr 失败 ");
        fclose(pFILE);
    }
    //这块内存 是 保存了 so文件里面的 全部的 字符串信息
    //也就是 dynstr表 的 全部 数据 dynstr表包含 dynsym表
    //dynsym表 都是一些动态 数据 比如函数名字 之类的 而dynstr包含 全部数据
    symstr = (char *) malloc(dynsym_str_size * sizeof(char));

    // 将整个字符表读入symstr中
    fread(symstr, sizeof(char), (size_t) dynsym_str_size, pFILE);



    // 移动文件指针到符号表位置 dynsym表
    if (fseek(pFILE, dynsym_off, SEEK_SET) != 0) {
        LOGE("文件移动到 dynsym 失败 ");
        fclose(pFILE);
    }

    //将字符串 表 添加到 集合里
    //总共的大小/每一个大小 == 个数
    dynsym_entry_num = dynsym_size / sizeof(Elf32_Sym);

    for (int y = 0; y < dynsym_entry_num; y++) {
        // 将 数据 放到 指定位置  符号表 （（例如定义全局变量时使用的变量名，
        // 或者定义函数时使用的函数名））
        //分配 单一 Elf32_Sym 大小的内存
        Elf32_Sym *elf32_sym_array = (Elf32_Sym *) malloc(sizeof(Elf32_Sym));
        fread(elf32_sym_array, sizeof(Elf32_Sym), 1, pFILE);

        //当前 符号表的 内容
        char *s_name;
        // 从节名字符数组中获取节名称字符串
        //用的是 -> 这个是 二级指针  .是一级指针
        //elf32_sym_array 本身是个 地址 需要先拿到
        // 对应的内容 在拿到 数据里面的信息 所以是 二级指针
        s_name = &(symstr[elf32_sym_array->st_name]);

        //将 当前 符号表的 内容打印出来
        LOGE(" dynsym表 遍历  位置 %d  数据详情 %s", y, s_name);
    }
}

void fenge(char *str,char* SectionList[]) {
    char * fen= (char *) "\0";
    char *p;
//    while ((p=strtok(str,fen))){
//        SectionList[]
//    }

    LOGE("分割 666 %s",strtok(str,fen));
    for(int i=0;i<elf_head.e_shnum;i++){
        LOGE("分割 %s",strtok(NULL,fen));
        SectionList[i]=strtok(NULL,fen);
    }
}


void analyzeSection(FILE *pFILE) {


    LOGE("开始 解析 Section");
    // 文件指针移动到程序头 偏移
    LOGE("偏移位置  %d", elf_head.e_shoff);

    if (fseek(pFILE, (long) elf_head.e_shoff, SEEK_SET) != 0) {
        LOGE("移动到节头 失败");
        fclose(pFILE);
    } else {
        long i = ftell(pFILE);
        LOGE("fseek成功 file当前位置 %d", i);
    }


    LOGE("Section字段 Item的 个数 %d  节头偏移开始位置 %d", elf_head.e_shnum, elf_head.e_shoff);
    for (int i = 0; i < elf_head.e_shnum; i++) {

        Elf32_Shdr *SItem = new Elf32_Shdr();

        size_t PItem_size = fread(SItem, 1, sizeof(Elf32_Shdr), pFILE);
        if (PItem_size != 0) {
            LOGE("Section Item 匹配成功 总个数%d  当前的 Item %d", elf_head.e_phnum, i);
        } else {
            LOGE("Section Item  错误原因%d", PItem_size);
            return;
        }

        if (SItem->sh_name == NULL) {
            LOGE("Section Item  Section 名字 SHT_UNDEF");
        } else {

            LOGE("在 SectionTabStr 的 总长度%d   sizeof %d", strlen(SectionTabStr),
                 sizeof(SectionTabStr));
            LOGE("在 SectionTabStr 的 内容   %s", SectionTabStr);


            LOGE("在 SectionTabStr 的 位置 %d", SItem->sh_name);

            LOGE("Section Item  Section 名字 %s", (char *) (SectionTabStr[SItem->sh_name]));
        }
        LOGE("Section Item  Section 节区类型 %d", SItem->sh_type);
        LOGE("Section Item  Section 节区标志 %d", SItem->sh_flags);
        LOGE("Section Item  Section 节区索引地址 %x", SItem->sh_addr);
        LOGE("Section Item  Section 节区偏移  节区相对于文件的偏移地址 %x", SItem->sh_offset);
        LOGE("Section Item  Section 节区长度（大小）   %d", SItem->sh_size);
        LOGE("Section Item  Section 节区头部表索引链接  和此字节有关联的节索引位置 %d", SItem->sh_link);
        LOGE("Section Item  Section 附加信息  如果 sh_link 为 0 sh_info也为 0 %d", SItem->sh_info);
        LOGE("Section Item  Section 对齐约束   %d", SItem->sh_addralign);
        LOGE("Section Item  Section 节区表项大小   %d", SItem->sh_entsize);


    }

}

//位置
char *getSectionString(Elf32_Word name) {
    return (char *) SectionTabStr[name];
}


void analyzeProgram(FILE *pFILE) {
    LOGE("开始 解析 Program字段 ");
    // 文件指针移动到程序头 偏移
    if (fseek(pFILE, (long) elf_head.e_phoff, SEEK_SET) != 0) {
        LOGE("移动到程序头 失败");
        fclose(pFILE);
    }
    LOGE("Program字段 Item的 个数 %d", elf_head.e_phnum);
    for (int i = 0; i < elf_head.e_phnum; i++) {
        Elf32_Phdr PItem;
        size_t PItem_size = fread(&PItem, sizeof(Elf32_Phdr), 1, pFILE);
        if (PItem_size != 0) {
            LOGE("Program Item 匹配成功 总个数%d  当前的 Item %d", elf_head.e_phnum, i);
        } else {
            LOGE("Program Item  错误原因%d", PItem_size);
            return;
        }

        LOGE("Program Item  描述段的类型 p_type %d", PItem.p_type);
        LOGE("Program Item  段偏移 当前所在程序段（Segment）开始地址 p_offset %d", PItem.p_offset);
        LOGE("Program Item  虚拟地址 段在（内存）中的虚拟地址  p_vaddr %#x", PItem.p_vaddr);
        LOGE("Program Item  段物理地址 绝对地址  p_paddr %#x", PItem.p_paddr);

        LOGE("Program Item  在文件中的大小  p_filesz %d", PItem.p_filesz);
        LOGE("Program Item  在内存中的大小  p_memsz %d", PItem.p_memsz);
        LOGE("Program Item  段相关标识(read、write、exec)  p_flags %d", PItem.p_flags);
        LOGE("Program Item  对齐取值  p_align %d", PItem.p_align);
    }
}

//%a,%A 读入一个浮点值(仅C99有效) 　　
//%c 读入一个字符 　　
//%d 读入十进制整数 　　
//%i 读入十进制，八进制，十六进制整数 　　
//%o 读入八进制整数 　　
//%x,%X 读入十六进制整数 　　
//%s 读入一个字符串，遇空格、制表符或换行符结束。 　　
//%f,%F,%e,%E,%g,%G 用来输入实数，可以用小数形式或指数形式输入。 　　
//%p 读入一个指针 　　
//%u 读入一个无符号十进制整数 　　
//%n 至此已读入值的等价字符数 　　
//%[] 扫描字符集合 　　
//%% 读%符号
void analyzeHead(Elf32_Ehdr elf_head) {

    LOGE("ELF 标识 %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
         elf_head.e_ident[0],
         elf_head.e_ident[1],
         elf_head.e_ident[2],
         elf_head.e_ident[3],
         elf_head.e_ident[4],
         elf_head.e_ident[5],
         elf_head.e_ident[6],
         elf_head.e_ident[7],
         elf_head.e_ident[8],
         elf_head.e_ident[9],
         elf_head.e_ident[10],
         elf_head.e_ident[11],
         elf_head.e_ident[12],
         elf_head.e_ident[13],
         elf_head.e_ident[14],
         elf_head.e_ident[15]
    );


    LOGE("类型 %x", elf_head.e_type);
    LOGE("目标体系结构类型 %d", elf_head.e_machine);
    LOGE("目标文件版本 %d", elf_head.e_version);
    LOGE("程序入口的虚拟地址，如果没有则为0 %x", elf_head.e_entry);
    LOGE("程序头部表偏移 %d", elf_head.e_phoff);
    LOGE("节区头部表偏移 %d", elf_head.e_shoff);
    LOGE("与文件相关，特定于处理器标志，4个字节 %d", elf_head.e_flags);
    LOGE("elf头部大小 %d", elf_head.e_ehsize);
    LOGE("Program_header 里面每一个Item大小 %d", elf_head.e_phentsize);
    LOGE("Program_header Item的 个数 %d", elf_head.e_phnum);
    LOGE("Selection_header 里面每一个Item大小 %d", elf_head.e_shentsize);
    LOGE("Selection_header Item的 个数 %d", elf_head.e_shnum);
    LOGE("节区头部表格中与节区名称字符串表相关的表项索引 %d", elf_head.e_shstrndx);


}

//检测 ELF文件 先确定 文件 是否是 elf类型
bool checkELF(Elf32_Ehdr elf_head) {
    return !(elf_head.e_ident[0] != 0x7F || elf_head.e_ident[1] != 'E' ||
             elf_head.e_ident[2] != 'L' || elf_head.e_ident[3] != 'F');
}

void Test() {


}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint resultstr = -1;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    jclass jclazz = env->FindClass("so/make/com/soanalyzeforc/MainActivity");

    JNINativeMethod natives[] = {
            {"Main", "()V", (void *) Main},
            {"Test", "()V", (void *) Test}

    };
    env->RegisterNatives(jclazz, natives, 2);


    env->DeleteLocalRef(jclazz);

    return JNI_VERSION_1_6;
}