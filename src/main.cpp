#define PACKAGE 1
#define PACKAGE_VERSION 1
#include <iostream>
#include <bfd.h>
#include "loader.h"
#define filename "/home/hero/a.out"

int main(int argc, char* argv[]){
    size_t i = 0;
    Binary bin;
    Symbol* sym = nullptr;
    std::string fname = filename;

    if(argc < 2){
        printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    fname = ("/home/hero/a.out");
    if(loader::load_binary(fname.c_str(), &bin, Binary::BIN_TYPE_AUTO) < 0){
        return 1;
    }

    printf("Loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n", fname.c_str(), bin.type_str.c_str(), bin.arch_str.c_str(), bin.bits, bin.entry);

    for(int i = 0; i < bin.sections.size(); i++){
        printf("  0x%016jx %-8ju %-20s %s\n", bin.sections[i].vma, bin.sections[i].size, bin.sections[i].name.c_str(), bin.sections[i].type== Section::SEC_TYPE_CODE ? "CODE" :"DATA");
    }

    if(bin.symbols.size() > 0){
        printf("scanned symbol tables\n");
        for(i = 0; i < bin.symbols.size(); i++){
            sym = &bin.symbols[i];

            printf("   %-40s 0x%016jx %s\n", sym->name.c_str(), (sym->addr, sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "");
        }
    }
    return 0;
}
