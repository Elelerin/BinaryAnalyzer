

#ifndef LOADER_H
#define LOADER_H
#define PACKAGE 1
#define PACKAGE_VERSION 1
#include <stdlib.h>
#include <stdint.h>
#include <bfd.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <format>
class Binary;

class Section
{
    public:
        enum SectionType{
            SEC_TYPE_NONE = 0,
            SEC_TYPE_CODE = 1,
            SEC_TYPE_DATA = 2
        };


        Section(Binary* _binary, std::string _name, SectionType _type, uint64_t _vma, uint64_t _size, std::unique_ptr<uint8_t[]> _bytes) :
            binary(_binary), name(_name), type(_type), vma(_vma), size(_size), bytes(std::move(_bytes)) {};


        Section(const Section& oldSection){
            binary = oldSection.binary;
            name = oldSection.name;
            type = oldSection.type;
            vma = oldSection.vma;
            size = oldSection.size;
        }


        ~Section(){
            binary = nullptr;
        }


        Binary* binary;
        std::string name;
        SectionType type;
        uint64_t vma;
        uint64_t size;
        std::unique_ptr<uint8_t[]> bytes;

};



class Symbol{
    public:
        enum SymbolType {
            SYM_TYPE_UKN = 0,
            SYM_TYPE_FUNC = 1
        };

        Symbol() :type(SYM_TYPE_UKN), name(), addr(0) {}
        Symbol(SymbolType _type, std::string _name, uint64_t _addr){
            type = _type;
            name = _name;
            addr = _addr;
        }
        SymbolType      type;
        std::string     name;
        uint64_t        addr;
};

class Binary{
    public:
        Binary() : type(BIN_TYPE_AUTO), arch(ARCH_NONE), bits(1), entry(0) {};
        ~Binary() {};

        enum BinaryType{
            BIN_TYPE_AUTO = 0,
            BIN_TYPE_ELF = 1,
            BIN_TYPE_PE = 2
        };

        enum BinaryArch{
            ARCH_NONE = 0,
            ARCH_X86 = 1
        };

        std::unique_ptr<Section> getTextSection(){
            for(auto &s : sections){
                if(s.name == ".text"){
                    return std::unique_ptr<Section>(&s);
                }return nullptr;
            }
        }

        std::string filename;
        BinaryType type;
        std::string type_str;
        BinaryArch arch;
        std::string arch_str;
        unsigned bits;
        uint64_t entry;

        std::vector<Section> sections;
        std::vector<Symbol> symbols;


};

namespace loader{
       inline void printFail(const std::string failureString){
            std::cout << failureString << std::endl;
        };


        static int load_sections_bfd(bfd* bfd_h, Binary *bin){
            Section::SectionType sectype = Section::SEC_TYPE_NONE;
            int bfd_flags = -1;
            uint64_t size = 0;
            std::string name = "\0";
            for(asection* bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next){
                bfd_flags = bfd_sec->flags;
                sectype = Section::SEC_TYPE_NONE;

                if(bfd_flags & SEC_DATA){
                    sectype =  Section::SEC_TYPE_DATA;
                }else if(bfd_flags & SEC_CODE){
                    sectype = Section::SEC_TYPE_CODE;
                }else{
                    continue;
                }

                cont:
                size = bfd_section_size(bfd_sec);

                std::unique_ptr<uint8_t[]> pass = std::make_unique<uint8_t[]>(size);
                Section section(bin, bfd_section_name(bfd_sec),
                                 sectype, (uint64_t)bfd_section_vma(bfd_sec), size, std::move(pass));

                bin->sections.emplace_back(section);

                if(!bfd_get_section_contents(bfd_h, bfd_sec, section.bytes.get(), 0, size)){
                    loader::printFail("Failed to Read Binary");
                    return -1;
                }
            }
            return 0;
        }

        //BFD IS PASSED IN AS A POINTER AND DESTROYED IN OUTER FUNCTION
        static int load_symbols_bfd(bfd* bfd_h, Binary* bin){
            long n = bfd_get_symtab_upper_bound(bfd_h);
            if(n < 0){
                loader::printFail("Failed to get Symbol");
                return -1;
            }

            asymbol** bfd_symtab = (asymbol**)malloc(n);
            if(!bfd_symtab){return -1;}
            long nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
            if(nsyms < 0){
                loader::printFail("failed to read symtab");
                return -1;
            }

            for(int i = 0; i < nsyms; i++){
                if(bfd_symtab[i]->flags & BSF_FUNCTION){
                    Symbol toPush(Symbol::SYM_TYPE_FUNC, std::string(bfd_symtab[i]->name), bfd_asymbol_value(bfd_symtab[i]));
                    bin->symbols.emplace_back(toPush);
                }
            }

            if(bfd_symtab) { free(bfd_symtab); }
            return 0;
        }

        static int load_dynsym_bfd(bfd* bfd_h, Binary* bin){
            long n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
            if(n < 0){
                loader::printFail("Failed to get Symbol");
                return -1;
            }

            asymbol** bfd_dynsim = (asymbol**)malloc(n);
            if(!bfd_dynsim){return -1;}


            long nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsim);
            if(nsyms < 0){
                loader::printFail("failed to read symtab");
                return -1;
            }

            for(int i = 0; i < nsyms; i++){
                if(bfd_dynsim[i]->flags & BSF_FUNCTION){
                    Symbol toPush(Symbol::SYM_TYPE_FUNC, std::string(bfd_dynsim[i]->name), bfd_asymbol_value(bfd_dynsim[i]));
                    bin->symbols.emplace_back(toPush);
                }
            }

            if(bfd_dynsim) { free(bfd_dynsim); }
            return 0;
        }

        static std::unique_ptr<bfd> open_bfd(const char* fname){
            static int bfd_inited = 0;

            if(!bfd_inited){
                bfd_init();
                bfd_inited = 1;
            }

            std::unique_ptr<bfd> bfd_h = std::unique_ptr<bfd>(bfd_openr(fname, nullptr));
            if(bfd_h.get() == nullptr){
                fprintf(stderr, "failed to open binary %s (%s)\n", fname, bfd_errmsg(bfd_get_error()));
                return nullptr;
            }

            if(!bfd_check_format(bfd_h.get(), bfd_object)){
                fprintf(stderr, "not binary: %s (%s)\n", fname, bfd_errmsg(bfd_get_error()));
                return nullptr;
            }

            bfd_set_error(bfd_error_no_error);

            if(bfd_get_flavour(bfd_h.get()) == bfd_target_unknown_flavour){
                fprintf(stderr, "this tastes strange: %s (%s)\n", fname, bfd_errmsg(bfd_get_error()));
                return nullptr;
            }

            return bfd_h;
        }

        static int load_binary_bfd(const char* fname, Binary* bin, Binary::BinaryType type){
            bfd* bfd_h = open_bfd(fname).release();
            const bfd_arch_info_type* bfd_info = bfd_get_arch_info(bfd_h);

            if(!bfd_h) { return -1; }

            bin->filename = std::string(fname);
            bin->entry = bfd_get_start_address(bfd_h);
            bin->type_str = std::string(bfd_h->xvec->name);
            switch(bfd_h->xvec->flavour){
            case bfd_target_elf_flavour:
                bin->type = Binary::BIN_TYPE_ELF;
                break;
            case bfd_target_coff_flavour:
                bin->type = Binary::BIN_TYPE_PE;
                break;
            default:
                fprintf(stderr, "binary type bad, (%s)\n", bfd_h->xvec->name);
                bfd_close(bfd_h);
                return -1;
            }


            bin->arch_str = std::string(bfd_info->printable_name);
            switch(bfd_info->mach){
            case bfd_mach_i386_i386:
                bin->arch = Binary::ARCH_X86;
                bin->bits <<= 5;
                break;
            case bfd_mach_x86_64:
                bin->arch = Binary::ARCH_X86;
                bin->bits <<= 6;
                break;
            default:
                fprintf(stderr, "binary type bad, (%s)\n", bfd_h->xvec->name);
                bfd_close(bfd_h);
                return -1;
            }
            load_sections_bfd(bfd_h, bin);
            load_symbols_bfd(bfd_h, bin);
            load_dynsym_bfd(bfd_h, bin);

            if(bfd_h){ bfd_close(bfd_h); }
            return 0;

        }


        inline int load_binary(const char* fname, Binary* bin, Binary::BinaryType type){ return loader::load_binary_bfd(fname, bin, type); };

        void unload_binary(Binary *bin);

}

#endif //LOADER_H
