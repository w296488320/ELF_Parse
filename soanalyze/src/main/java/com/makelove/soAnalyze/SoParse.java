package com.makelove.soAnalyze;

import com.makelove.soAnalyze.bean.ElfType32;

/**
 * Created by lyh on 2018/11/7.
 */

public class SoParse {


    private static ElfType32 type_32 = new ElfType32();

    /**
     * 解析Elf的头部信息
     *
     * @param header
     */
    public static void parseHeader(byte[] header, int offset) {
        if (header == null) {
            LogUtils.e("header is null");
            return;
        }
        /**
         *  public byte[] e_ident = new byte[16];
         public short e_type;
         public short e_machine;
         public int e_version;
         public int e_entry;
         public int Program_header_off;
         public int Section_header_off;
         public int e_flags;
         public short e_ehsize;
         public short e_phentsize;
         public short e_phnumCount;
         public short e_shentsize;
         public short e_shnumCount;
         public short e_shstrndx;
         */
        type_32.hdr.e_ident = Utils.copyBytes(header, 0, 16);//魔数

        type_32.hdr.e_type = Utils.copyBytes(header, 16, 2);

        type_32.hdr.e_machine = Utils.copyBytes(header, 18, 2);
        type_32.hdr.e_version = Utils.copyBytes(header, 20, 4);
        type_32.hdr.e_entry = Utils.copyBytes(header, 24, 4);
        type_32.hdr.Program_header_off = Utils.copyBytes(header, 28, 4);
        type_32.hdr.Section_header_off = Utils.copyBytes(header, 32, 4);
        type_32.hdr.e_flags = Utils.copyBytes(header, 36, 4);
        type_32.hdr.e_ehsize = Utils.copyBytes(header, 40, 2);
        type_32.hdr.e_phentsize = Utils.copyBytes(header, 42, 2);
        type_32.hdr.e_phnumCount = Utils.copyBytes(header, 44, 2);
        type_32.hdr.e_shentsize = Utils.copyBytes(header, 46, 2);
        type_32.hdr.e_shnumCount = Utils.copyBytes(header, 48, 2);
        type_32.hdr.e_shstrndx = Utils.copyBytes(header, 50, 2);
    }


    /**
     * 解析段头信息内容
     */
    public static void parseSectionHeaderList(byte[] header) {
        int offset = Utils.byte2Int(type_32.hdr.Section_header_off);

        int header_size = 40;//40个字节
        int header_count = Utils.byte2Short(type_32.hdr.e_shnumCount);//头部的个数
        byte[] des = new byte[header_size];
        for (int i = 0; i < header_count; i++) {
            System.arraycopy(header, i * header_size + offset, des, 0, header_size);

            //type_32.shdrList.add(parseSectionHeader(des));
        }
    }


    /**
     * 解析程序头信息
     *
     * @param header
     */
    public static void parseProgramHeaderList(byte[] header) {
        int offset = Utils.byte2Int(type_32.hdr.Program_header_off);
        //每一个大小都是 0x16-》32字节
        int header_size = 32;//32个字节
        int header_count = Utils.byte2Short(type_32.hdr.e_phnumCount);//头部的个数
        byte[] des = new byte[header_size];
        for (int i = 0; i < header_count; i++) {
            //参数
            //1,原数组
            //2,原数组开始 位置
            //3,赋值的数组
            //4,赋值的数组的开始位置
            //5,长度
            System.arraycopy(header, i * header_size + offset,
                    des, 0, header_size);
            type_32.ProgramHeaderList.add(parseProgramHeader(des));
        }
    }


    private static ElfType32.Elf32_ProgramHeeaderItem parseProgramHeader(byte[] header) {
        /**
         public int p_type;
         public int p_offset;
         public int p_vaddr;
         public int p_paddr;
         public int p_filesz;
         public int p_memsz;
         public int p_flags;
         public int p_align;
         */
        ElfType32.Elf32_ProgramHeeaderItem phdr = new ElfType32.Elf32_ProgramHeeaderItem();
        phdr.p_type = Utils.copyBytes(header, 0, 4);
        phdr.p_offset = Utils.copyBytes(header, 4, 4);
        phdr.p_vaddr = Utils.copyBytes(header, 8, 4);
        phdr.p_paddr = Utils.copyBytes(header, 12, 4);
        phdr.p_filesz = Utils.copyBytes(header, 16, 4);
        phdr.p_memsz = Utils.copyBytes(header, 20, 4);
        phdr.p_flags = Utils.copyBytes(header, 24, 4);
        phdr.p_align = Utils.copyBytes(header, 28, 4);
        return phdr;

    }


}
