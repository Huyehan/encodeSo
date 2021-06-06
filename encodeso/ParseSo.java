package parseso;

public class ParseSo {
    public static ElfType32 type_32=new ElfType32();
    private static String encodeSectionName=".mytext";

    public static void main(String[] args) {
        byte[] fileByteArys=Utils.readFile("F:\\AndroidStudioProjects\\encodefunction\\app\\release\\libnative-lib.so");
        if (fileByteArys==null){
            System.out.println("read file byte failed...");
            return;
        }
        parseSo(fileByteArys);
        encodeFunction(fileByteArys);
//        encodeSection(fileByteArys);
        Utils.saveFile("F:\\AndroidStudioProjects\\encodefunction\\app\\release\\libnative-encode.so",fileByteArys);
    }
    private static String functionName="Java_com_example_encodefunction_MainActivity_stringFromJNI";

    private static void encodeFunction(byte[] fileByteArys){
        int dy_offset=0,dy_size=0;
        // 在程序头表中找到.dynamic并获取偏移地址和大小
        for (ElfType32.elf32_phdr phdr : type_32.phdrList) {
            if (Utils.byte2Int(phdr.p_type)==2){ // PT_DYNAMIC
                dy_offset=Utils.byte2Int(phdr.p_offset);
                dy_size=Utils.byte2Int(phdr.p_filesz);
            }
        }
        int dynSize=8;
        int size=dy_size / dynSize;
        byte[] dest=new byte[dynSize];
        // 解析.dynamic的数据内容
        for (int i = 0; i < size; i++) {
            System.arraycopy(fileByteArys,dy_offset+i*dynSize,dest,0,dynSize);
            type_32.dynList.add(parseDynamic(dest));
        }

        byte[] symbolStr=null;
        int strSize=0,strOffset=0;
        int symbolOffset=0;
        int dynHashOffset=0;
        int funcIndex=0;
        int symbolSize=16;
        for (ElfType32.elf32_dyn dyn : type_32.dynList) {
            if (Utils.byte2Int(dyn.d_tag)==4){ //DT_HASH
                // 获取.hash段的偏移地址
                dynHashOffset=Utils.byte2Int(dyn.d_ptr);
            }else if (Utils.byte2Int(dyn.d_tag)==5){ //DT_STRTAB
                // 获取.dynstr段的偏移地址
                strOffset=Utils.byte2Int(dyn.d_ptr);
            }else if (Utils.byte2Int(dyn.d_tag)==6){ //DT_SYMTAB
                // 获取.dynsym段的偏移地址
                symbolOffset=Utils.byte2Int(dyn.d_ptr);
            }else if (Utils.byte2Int(dyn.d_tag)==10){ //DT_STRSZ
                // 获取.dynstr段的大小
                strSize=Utils.byte2Int(dyn.d_val);
            }
        }
        // 获取所有函数的名称
        symbolStr=Utils.copyBytes(fileByteArys,strOffset,strSize);
        for (ElfType32.elf32_dyn dyn : type_32.dynList) {
            if (Utils.byte2Int(dyn.d_tag)==4){ // DT_HASH
                int nbucket=Utils.byte2Int(Utils.copyBytes(fileByteArys,dynHashOffset,4));
                int nchain=Utils.byte2Int(Utils.copyBytes(fileByteArys,dynHashOffset+4,4));
                int hash=(int) elfhash(functionName.getBytes());
                hash=hash%nbucket;
                funcIndex=Utils.byte2Int(Utils.copyBytes(fileByteArys,
                        dynHashOffset+hash*4+8,4));
                byte[] des=new byte[symbolSize];
                System.arraycopy(fileByteArys,symbolOffset+symbolSize*funcIndex,
                        des,0,symbolSize);
                ElfType32.Elf32_Sym sym = parseSymbolTable(des);
                boolean isFindFunction=Utils.isEqualByteAry(symbolStr,Utils.byte2Int(sym.st_name),functionName);
                if (isFindFunction){
                    System.out.println("find function...");
                    break;
                }
                while (true){
                    funcIndex=Utils.byte2Int(Utils.copyBytes(fileByteArys,
                            dynHashOffset+4*(2+nbucket+funcIndex),4));
                    System.arraycopy(fileByteArys,symbolOffset+funcIndex*symbolSize,
                            des,0,symbolSize);
                    sym=parseSymbolTable(des);
                    isFindFunction=Utils.isEqualByteAry(symbolStr,Utils.byte2Int(sym.st_name),functionName);
                    if (isFindFunction){
                        System.out.println("find function...");
                        // 读取函数进行加密
                        int funcSize=Utils.byte2Int(sym.st_size);
                        int funcOffset=Utils.byte2Int(sym.st_value);
                        System.out.println("offset:"+funcOffset+",size:"+funcSize);
                        byte[] funcAry=Utils.copyBytes(fileByteArys,funcOffset,funcSize);
                        for (int i = 0; i < funcAry.length; i++) {
                            funcAry[i]= (byte) (funcAry[i]^0xFF);
                        }
                        Utils.replaceByteAry(fileByteArys,funcOffset,funcAry);

                        byte[] entry=Utils.int2Byte(funcSize);
                        // 用大小替换e_entry
                        Utils.replaceByteAry(fileByteArys,24,entry);
                        byte[] offsetAry=Utils.int2Byte(funcOffset);
                        // 用偏移地址替换e_flags
                        Utils.replaceByteAry(fileByteArys,36,offsetAry);
                        break;
                    }
                }
                break;
            }
        }
    }

    // hash函数
    private static long elfhash(byte[] bytes) {
        long h=0,g;
        for (byte b : bytes) {
            h=(h<<4)+b;
            g=h & 0xf0000000;
            h^=g;
            h^=g>>24;
        }
        return h;
    }

    private static ElfType32.elf32_dyn parseDynamic(byte[] src) {
        ElfType32.elf32_dyn dyn=new ElfType32.elf32_dyn();
        dyn.d_tag=Utils.copyBytes(src,0,4);
        dyn.d_val=Utils.copyBytes(src,4,4);
        dyn.d_ptr=Utils.copyBytes(src,4,4);
        return dyn;
    }

    private static void encodeSection(byte[] fileByteArys) {
        // 读取String Section段
        int string_section_index=Utils.byte2Short(type_32.hdr.e_shstrndx);
        ElfType32.elf32_shdr shdr=type_32.shdrList.get(string_section_index);
        int size=Utils.byte2Int(shdr.sh_size);
        int offset=Utils.byte2Int(shdr.sh_offset);
        int mySectionOffset=0,mySectionSize=0;
        for (ElfType32.elf32_shdr temp:type_32.shdrList){
            int sectionNameOffset=offset+Utils.byte2Int(temp.sh_name);
            if (Utils.isEqualByteAry(fileByteArys,sectionNameOffset,encodeSectionName)){
                // 读取section段进行加密
                mySectionOffset=Utils.byte2Int(temp.sh_offset);
                mySectionSize=Utils.byte2Int(temp.sh_size);
                byte[] sectionAry=Utils.copyBytes(fileByteArys,mySectionOffset,mySectionSize);
                for (int i = 0; i < sectionAry.length; i++) {
                    sectionAry[i]= (byte) (sectionAry[i] ^ 0xFF);
                }
                Utils.replaceByteAry(fileByteArys,mySectionOffset,sectionAry);
            }
        }
        // 修改ELF Header中的entry和flags
        int nSize=mySectionSize/4096+(mySectionSize%4096 == 0 ? 0 : 1);
        byte[] entry=new byte[4];
        entry=Utils.int2Byte(mySectionSize);
        // 用大小替换e_entry
        Utils.replaceByteAry(fileByteArys,24,entry);
        byte[] offsetAry=new byte[4];
        offsetAry=Utils.int2Byte(mySectionOffset);
        // 用偏移地址替换e_flags
        Utils.replaceByteAry(fileByteArys,36,offsetAry);
    }

    private static void parseSo(byte[] fileByteArys) {
        // 读取头部信息
        System.out.println("++++++++ELF Header++++++++");
        parseHeader(fileByteArys,0);
        System.out.println("header:\n"+type_32.hdr);

        // 读取程序头信息
        System.out.println();
        System.out.println("+++++++Program Header+++++++");
        int p_header_offset=Utils.byte2Int(type_32.hdr.e_phoff);
        parseProgramHeaderList(fileByteArys,p_header_offset);
        type_32.printPhdrList();

        // 读取段头信息
        System.out.println();
        System.out.println("++++++++Section Header++++++++");
        int s_header_offset=Utils.byte2Int(type_32.hdr.e_shoff);
        parseSectionHeaderList(fileByteArys,s_header_offset);
        type_32.printShdrList();

        // 读取符号表信息
        System.out.println();
        System.out.println("++++++++Symbol Table++++++++");
        // TYPE=DYNSYM
        int offset_sym=0; // 符号表偏移
        int total_sym=0;
        for (ElfType32.elf32_shdr shdr : type_32.shdrList) {
            // 获取TYPE=DYNSYM(11)的段头
            if (Utils.byte2Int(shdr.sh_type)==ElfType32.SHT_DYNSYM){
                total_sym=Utils.byte2Int(shdr.sh_size);
                offset_sym=Utils.byte2Int(shdr.sh_offset);
                break;
            }
        }
        int num_sym = total_sym / 16;
        System.out.println("sym num="+num_sym);
        parseSymbolTableList(fileByteArys, num_sym, offset_sym);
        type_32.printSymList();

        // 读取字符串表信息
        System.out.println();
        System.out.println("++++++++String Table++++++++");
        // TYPE=STRTAB
        int strtab_offset=0;
        int strtab_size=0;
        for (ElfType32.elf32_shdr shdr : type_32.shdrList) {
            if (Utils.byte2Int(shdr.sh_type)==ElfType32.SHT_STRTAB){
                strtab_offset=Utils.byte2Int(shdr.sh_offset);
                strtab_size=Utils.byte2Int(shdr.sh_size);
                break;
            }
        }
        byte[] strtab=new byte[strtab_size];
        System.arraycopy(fileByteArys,strtab_offset,strtab,0,strtab_size);
        System.out.println(new String(strtab));
    }

    private static void parseSymbolTableList(byte[] header, int header_count, int offset) {
        int header_size=16; //16个字节
        byte[] des=new byte[header_size];
        for (int i = 0; i < header_count; i++) {
            System.arraycopy(header,offset+i*header_size,des,0,header_size);
            type_32.symList.add(parseSymbolTable(des));
        }
    }

    private static ElfType32.Elf32_Sym parseSymbolTable(byte[] header){
        ElfType32.Elf32_Sym sym = new ElfType32.Elf32_Sym();
        sym.st_name = Utils.copyBytes(header, 0, 4);
        sym.st_value = Utils.copyBytes(header, 4, 4);
        sym.st_size = Utils.copyBytes(header, 8, 4);
        sym.st_info = header[12];
        sym.st_other = header[13];
        sym.st_shndx = Utils.copyBytes(header, 14, 2);
        return sym;
    }

    private static void parseSectionHeaderList(byte[] header, int offset) {
        int header_size = 40; //40个字节
        int header_count = Utils.byte2Short(type_32.hdr.e_shnum); //段头表数目
        byte[] des = new byte[header_size];
        for(int i=0;i<header_count;i++){
            System.arraycopy(header, i*header_size + offset, des, 0, header_size);
            type_32.shdrList.add(parseSectionHeader(des));
        }
    }

    private static ElfType32.elf32_shdr parseSectionHeader(byte[] header) {
        ElfType32.elf32_shdr shdr = new ElfType32.elf32_shdr();
        shdr.sh_name = Utils.copyBytes(header, 0, 4);
        shdr.sh_type = Utils.copyBytes(header, 4, 4);
        shdr.sh_flags = Utils.copyBytes(header, 8, 4);
        shdr.sh_addr = Utils.copyBytes(header, 12, 4);
        shdr.sh_offset = Utils.copyBytes(header, 16, 4);
        shdr.sh_size = Utils.copyBytes(header, 20, 4);
        shdr.sh_link = Utils.copyBytes(header, 24, 4);
        shdr.sh_info = Utils.copyBytes(header, 28, 4);
        shdr.sh_addralign = Utils.copyBytes(header, 32, 4);
        shdr.sh_entsize = Utils.copyBytes(header, 36, 4);
        return shdr;
    }

    private static void parseProgramHeaderList(byte[] header, int offset) {
        int header_size=32; //32个字节
        int header_count=Utils.byte2Short(type_32.hdr.e_phnum); //程序头数目
        byte[] des=new byte[header_size];
        for (int i = 0; i < header_count; i++) {
            System.arraycopy(header,offset+i*header_size,des,0,header_size);
            type_32.phdrList.add(parseProgramHeader(des));
        }
    }

    private static ElfType32.elf32_phdr parseProgramHeader(byte[] header) {
        ElfType32.elf32_phdr phdr = new ElfType32.elf32_phdr();
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

    private static void parseHeader(byte[] header, int offset) {
        if (header==null){
            System.out.println("header is null...");
            return;
        }
        type_32.hdr.e_ident = Utils.copyBytes(header,0,16);//魔数
        type_32.hdr.e_type = Utils.copyBytes(header, 16, 2);
        type_32.hdr.e_machine = Utils.copyBytes(header, 18, 2);
        type_32.hdr.e_version = Utils.copyBytes(header, 20, 4);
        type_32.hdr.e_entry = Utils.copyBytes(header, 24, 4);
        type_32.hdr.e_phoff = Utils.copyBytes(header, 28, 4);
        type_32.hdr.e_shoff = Utils.copyBytes(header, 32, 4);
        type_32.hdr.e_flags = Utils.copyBytes(header, 36, 4);
        type_32.hdr.e_ehsize = Utils.copyBytes(header, 40, 2);
        type_32.hdr.e_phentsize = Utils.copyBytes(header, 42, 2);
        type_32.hdr.e_phnum = Utils.copyBytes(header, 44,2);
        type_32.hdr.e_shentsize = Utils.copyBytes(header, 46,2);
        type_32.hdr.e_shnum = Utils.copyBytes(header, 48, 2);
        type_32.hdr.e_shstrndx = Utils.copyBytes(header, 50, 2);
    }
}
