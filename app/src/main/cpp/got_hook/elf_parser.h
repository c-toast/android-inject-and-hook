//
// Created by ctoast on 2020/2/11.
//

#pragma once

#include <elf.h>
#include <cstdio>

#define STR_DYNSYM ".dynsym"
#define STR_DYNSTR ".dynstr"
#define STR_RELDYN ".rel.dyn"
#define STR_RELPLT ".rel.plt"

#ifdef __aarch64__
#define Elf32_Dyn Elf64_Dyn
#define Elf32_Rel Elf64_Rel
#define Elf32_Rela Elf64_Rela
#define Elf32_Sym Elf64_Sym
#define Elf32_Ehdr Elf64_Ehdr
#define Elf32_Phdr Elf64_Phdr
#define Elf32_Shdr Elf64_Shdr
#define Elf32_Nhdr Elf64_Nhdr
#define ELF32_R_SYM ELF64_R_SYM
#define ELF32_R_TYPE ELF64_R_TYPE

#define STR_RELDYN ".rela.dyn"
#define STR_RELPLT ".rela.plt"
#endif

class ElfParser {
public:
    char *elf_name_ = NULL;

    ElfParser(char* ElfName);

    ElfParser() = delete;

    ~ElfParser();

    const Elf32_Ehdr * read_elf_header();

    //section header string table is a section that store the name string of all sections
    //this function return the content of this section. and the string it return will be backup
    //as section_header_string_table_ in the class
    //return NULL if fail
    const char* read_section_header_string_table();

    //given the name of section and a pointer to store it, this function will find the header of
    //the section and store it in the place where pointer points to.
    //return -1 if fail
    int read_section_header(const char *SectionName, Elf32_Shdr *Section);

    //return the symbol vitual address in .rel.dyn or .rel.plt.
    //return NULL if fail
    void* get_symbol_got_item_vaddr(char *SymbolName);

    //only print the symbol in .dynsym
    //if symbol_name is NULL, it print all symbol in .dynsym
    void print_symbols_full_name(char *symbol_name=NULL);

    void print_all_section_name();

    long get_loadsegment_offset();//actually i don't understand why it work, maybe it's wrong

private:
    FILE *elf_file_ = NULL;
    Elf32_Ehdr *elf_header_ = NULL;
    char *section_header_string_table_ = NULL;  //section header string table, record the name of section
};