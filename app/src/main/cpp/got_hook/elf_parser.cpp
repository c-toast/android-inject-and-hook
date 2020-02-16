#include "elf_parser.h"

#include <cstdio>
#include <cstring>
#include <errno.h>

#include "got_hook_log.h"

ElfParser::ElfParser(char* ElfName) {
    int n = strlen(ElfName) + 1;
    elf_name_ = new char[n];
    memcpy(elf_name_, ElfName, n);
    elf_file_ = fopen(elf_name_, "rb");
    if (elf_file_ == NULL)
    {
        LOGE("[-] ElfParser: fail to open %s, errno is %d, reason is %s", elf_name_,errno, strerror(errno));
    }
}

ElfParser::~ElfParser() {
    if (elf_file_ != NULL)
        fclose(elf_file_);
    if (elf_header_ != NULL)
        delete elf_header_;
    if (section_header_string_table_ != NULL)
        delete[]section_header_string_table_;
}

const Elf32_Ehdr * ElfParser::read_elf_header() {
    if (elf_header_ != NULL)
    {
        return elf_header_;
    }
    //make sure that the file have been opened
    if (elf_file_ == NULL)
    {
        LOGE("[-] read_elf_header: fail to open %s", elf_name_);
        return NULL;
    }
    //read magic
    fseek(elf_file_, 0, SEEK_SET);
    char magic[4];
    fread(magic, 1, 4, elf_file_);
    if (strncmp(magic + 1, "ELF", 3) != 0)
    {
        LOGE("[-] read_elf_header: %s is not a elf file", elf_name_);
        return NULL;
    }
    //read file header
    elf_header_ = new Elf32_Ehdr;
    fseek(elf_file_, 0, SEEK_SET);
    fread(elf_header_, sizeof(Elf32_Ehdr), 1, elf_file_);
    return elf_header_;
}

//section header string table is a section that store the name string of all sections
//this function return the content of this section. and the string it return will be backup
//as section_header_string_table_ in the class
//return NULL if fail
const char* ElfParser::read_section_header_string_table() {
    if (section_header_string_table_ != NULL)
    {
        return section_header_string_table_;
    }
    read_elf_header();
    if (elf_header_ == NULL)	//currently the only situation that causes header become NULL is that the file is not elf
    {
        LOGE("[-] read_section_header_string_table: can not get section header string table because missing Elf header");
        return NULL;
    }

    Elf32_Shdr SecStrHeader;	//header of section headers string table
    auto Index = elf_header_->e_shstrndx;    //Index of section headers string table in section headers table
    fseek(elf_file_, elf_header_->e_shoff + Index * sizeof(Elf32_Shdr), SEEK_SET);	//seek the poision of section header of section headers string table in section headers
    fread(&SecStrHeader, sizeof(Elf32_Shdr), 1, elf_file_);  //read the section header
    section_header_string_table_ = new char[SecStrHeader.sh_size];   //allocate space to back up section headers string table

    fseek(elf_file_, SecStrHeader.sh_offset, SEEK_SET);//seek the offset of section headers string table
    fread(section_header_string_table_, SecStrHeader.sh_size, 1, elf_file_);    //read the content of section and back it up
    return section_header_string_table_;
}

//given the name of section and a pointer to store it, this function will find the header of
//the section and store it in the place where pointer points to.
//return -1 if fail
int ElfParser::read_section_header(const char *SectionName, Elf32_Shdr *Section) {
    read_section_header_string_table();
    if (section_header_string_table_ == NULL)	//make sure that the section headers string table have been found
    {
        LOGE("[-] read_section_header: fail to read section header %s because missing string table", SectionName);
        return -1;
    }
    Elf32_Shdr TmpHeader;
    char *TmpStr;
    int SectionHeadersNum = elf_header_->e_shnum;
    //we can assume that ElfHeader exists because the string table, which need ElfHeader to find, have been found
    fseek(elf_file_, elf_header_->e_shoff, SEEK_SET);
    for (int i = 0; i<SectionHeadersNum; i++)
    {
        fread(&TmpHeader, sizeof(Elf32_Shdr), 1, elf_file_);
        TmpStr = section_header_string_table_ + TmpHeader.sh_name;
        if (strcmp(TmpStr, SectionName) == 0)
        {
            *Section = TmpHeader;
            return 0;
        }
    }
    LOGE("[-] read_section_header: %s does not exist in %s", SectionName, elf_name_);
    return -1;
}

//return the symbol vitual address in .rel.dyn or .rel.plt.
//return NULL if fail
void* ElfParser::get_symbol_got_item_vaddr(char *SymbolName) {
    Elf32_Shdr dynsymHeader, dynstrHeader, reldynHeader, relpltHeader;
    void* ReturnOffset = NULL;
    long dynsymSymbolNum, reldynSymbolNum, relpltSymbolNum;

    //read the relative headers
    if (read_section_header(STR_DYNSYM, &dynsymHeader)<0 ||
        read_section_header(STR_DYNSTR, &dynstrHeader)<0 ||
        read_section_header(STR_RELDYN, &reldynHeader)<0 ||
        read_section_header(STR_RELPLT, &relpltHeader)<0)
    {
        LOGE("[-] get_symbol_got_item_offset: fail to get symbol offset because missing some section");
        return NULL;
    }

    //read the section according to the information from section header
    dynsymSymbolNum = dynsymHeader.sh_size / sizeof(Elf32_Sym);//number of symbol in .dynsym;
    reldynSymbolNum = reldynHeader.sh_size / sizeof(Elf32_Rel);
    relpltSymbolNum = relpltHeader.sh_size / sizeof(Elf32_Rel);
    char *dynstr = new char[dynstrHeader.sh_size];
    Elf32_Sym *dynsym = new Elf32_Sym[dynsymSymbolNum];
    Elf32_Rel *reldyn = new Elf32_Rel[reldynSymbolNum];
    Elf32_Rel *relplt = new Elf32_Rel[relpltSymbolNum];

    fseek(elf_file_, dynstrHeader.sh_offset, SEEK_SET);
    fread(dynstr, dynstrHeader.sh_size, 1, elf_file_);

    fseek(elf_file_, dynsymHeader.sh_offset, SEEK_SET);
    fread(dynsym, sizeof(Elf32_Sym), dynsymSymbolNum, elf_file_);

    fseek(elf_file_, reldynHeader.sh_offset, SEEK_SET);
    fread(reldyn, sizeof(Elf32_Rel), reldynSymbolNum, elf_file_);

    fseek(elf_file_, relpltHeader.sh_offset, SEEK_SET);
    fread(relplt, sizeof(Elf32_Rel), relpltSymbolNum, elf_file_);

    for (int i = 0; i<reldynSymbolNum; i++)	//traverse the .rel.dyn
    {
        uint16_t SymIndex = ELF32_R_SYM(reldyn[i].r_info);	//get one .rel.dyn symbol index in .dynsym
        if (SymIndex > dynsymSymbolNum)
        {
            continue;
        }
        char *reldynSymName = dynsym[SymIndex].st_name + dynstr;
        LOGD("[d] symbol name in .rel.dyn: %s",reldynSymName);
        if (strstr(reldynSymName, SymbolName) != 0)
        {
            ReturnOffset = (void*)relplt[i].r_offset;
            LOGI("[+] find %s got item from .rel.dyn, vaddr is %p", reldynSymName, ReturnOffset);
            goto RETURN_RESULT;
        }
    }

    for (int i = 0; i<relpltSymbolNum; i++)	//traverse the .rel.plt
    {
        uint16_t SymIndex = ELF32_R_SYM(relplt[i].r_info);	//get one .rel.plt symbol index in .dynsym
        if (SymIndex > dynsymSymbolNum)
        {
            continue;
        }
        char *relpltSymName = dynsym[SymIndex].st_name + dynstr;
        LOGD("[d] function name in .rel.plt: %s",relpltSymName);
        if (strstr(relpltSymName, SymbolName) != 0)
        {
            ReturnOffset = (void*)relplt[i].r_offset;
            LOGI("[+] find the item of %s in .rel.plt, the vaddr the item record is %p", relpltSymName, ReturnOffset);
            goto RETURN_RESULT;
        }
    }
    LOGE("[-] get_symbol_got_item_offset: fail to find %s", SymbolName);

    RETURN_RESULT:
    delete []dynstr;
    delete []dynsym;
    delete []reldyn;
    delete []relplt;
    return ReturnOffset;
}

//actually i don't understand why it work, maybe it's wrong
//return -1 if fail
long ElfParser::get_loadsegment_offset() {
    read_elf_header();
    if (elf_header_ == NULL)
    {
        LOGE("[-] get_loadsegment_offset: can not get load segment offset because missing elf header");
        return -1;
    }
    Elf32_Phdr ProgramHeaderTab;
    int ProgramHeaderNum = elf_header_->e_phnum;
    fseek(elf_file_, elf_header_->e_phoff, SEEK_SET);
    for (int i = 0; i < ProgramHeaderNum; i++)
    {
        fread(&ProgramHeaderTab, sizeof(Elf32_Phdr), 1, elf_file_);
        if (ProgramHeaderTab.p_type == 1)
        {
            LOGI("[+] load segment vaddr of %s is %p", elf_name_,ProgramHeaderTab.p_vaddr);
            return ProgramHeaderTab.p_vaddr;
        }
    }
    LOGE("[-] get_loadsegment_offset: can not find load segment");
    return -1;
}

void ElfParser::print_all_section_name() {
    read_section_header_string_table();
    if (section_header_string_table_ == NULL)	//make sure that the section headers string table have been found
    {
        LOGE("[-] print_all_section_name: fail to print section name because missing string table");
        return;
    }
    Elf32_Shdr TmpHeader;
    char *TmpStr;
    int SectionHeadersNum = elf_header_->e_shnum;
    //we can assume that ElfHeader exists because the string table, which need ElfHeader to find, have been found
    fseek(elf_file_, elf_header_->e_shoff, SEEK_SET);
    for (int i = 0; i<SectionHeadersNum; i++)
    {
        fread(&TmpHeader, sizeof(Elf32_Shdr), 1, elf_file_);
        TmpStr = section_header_string_table_ + TmpHeader.sh_name;
        LOGI("[+] %s", TmpStr);
    }
}

//only print the symbol in .dynsym
//if symbol_name is NULL, it print all symbol in .dynsym
void ElfParser::print_symbols_full_name(char *symbol_name) {
    Elf32_Shdr dynsym_header, dynstr_header;
    int symbols_num;

    if (read_section_header(".dynsym", &dynsym_header) < 0 ||
        read_section_header(".dynstr", &dynstr_header) < 0) {
        LOGE("[-] print_symbols_full_name: fail to read the header of symtab or strtab");
        return;
    }

    symbols_num = dynsym_header.sh_size / sizeof(Elf32_Sym);
    Elf32_Sym *dynsym = new Elf32_Sym[symbols_num];
    char* dynstr = new char[dynstr_header.sh_size];

    fseek(elf_file_, dynsym_header.sh_offset, SEEK_SET);
    fread(dynsym, sizeof(Elf32_Sym), symbols_num, elf_file_);
    fseek(elf_file_, dynstr_header.sh_offset, SEEK_SET);
    fread(dynstr, dynstr_header.sh_size, 1, elf_file_);

    for (int i = 0; i<symbols_num; i++) {
        if(symbol_name!=NULL){
            if(strstr(dynsym[i].st_name+dynstr,symbol_name)!=NULL){
                LOGI("%s", dynsym[i].st_name + dynstr);
            }
        }
        else {
            LOGI("%s", dynsym[i].st_name + dynstr);
        }
    }
}
