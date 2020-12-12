#include "../udis86/udis86.h"

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <cstdint>


//size_t udx_gen_sig(uint8_t* mem_buffer, size_t mem_buffer_size,
//    char* sig_buffer, size_t sig_buffer_size, size_t insn_size, enum ud_match_lvl match_lvl) {
//    ud_t ud_obj;
//    ud_init(&ud_obj);
//    ud_set_input_buffer(&ud_obj, mem_buffer, mem_buffer_size);
//    ud_set_mode(&ud_obj, 32);
//    size_t insn_size_readed = 0, insn_sig_size, sig_size = 0;
//    const char* insn_sig;
//    memset(sig_buffer, 0, sig_buffer_size);
//    while (ud_disassemble(&ud_obj)) {
//        insn_sig = ud_insn_hex_sig(&ud_obj, match_lvl);
//        insn_sig_size = strlen(insn_sig);
//        if (strcat_s(sig_buffer, sig_buffer_size, insn_sig)) return 0;
//        sig_size += insn_sig_size;
//        sig_buffer += insn_sig_size;
//        sig_buffer_size -= insn_sig_size;
//        if (++insn_size_readed >= insn_size) break;
//    }
//    return sig_size;
//}
//size_t udx_gen_sig_rnd(uint8_t* mem_buffer, size_t mem_buffer_size,
//    char* sig_buffer, size_t sig_buffer_size, size_t insn_size) {
//    ud_t ud_obj;
//    ud_init(&ud_obj);
//    ud_set_input_buffer(&ud_obj, mem_buffer, mem_buffer_size);
//    ud_set_mode(&ud_obj, 32);
//    size_t insn_size_readed = 0, insn_sig_size, sig_size = 0;
//    const char* insn_sig;
//    memset(sig_buffer, 0, sig_buffer_size);
//    while (ud_disassemble(&ud_obj)) {
//        insn_sig = ud_insn_hex_sig(&ud_obj, (ud_match_lvl_t)(rand() % UD_MATCH_ALL));
//        insn_sig_size = strlen(insn_sig);
//        if (strcat_s(sig_buffer, sig_buffer_size, insn_sig)) return 0;
//        sig_size += insn_sig_size;
//        sig_buffer += insn_sig_size;
//        sig_buffer_size -= insn_sig_size;
//        if (++insn_size_readed >= insn_size) break;
//    }
//    return sig_size;
//}



int main()
{

    uint8_t data[] =
    {
       0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0xFF, 0x75, 0x08, 0xE8, 0x72, 0xFE, 0xFF, 0xFF, 0x8D, 0x4D,
       0x08, 0xC7, 0x45, 0x08, 0x04, 0x00, 0x00, 0x00, 0x51, 0x8D, 0x4D, 0xF8, 0x51, 0x8D, 0x4D, 0xFC,
       0x51, 0x6A, 0x00, 0xFF, 0x75, 0x0C, 0x50, 0xFF, 0x15, 0xE8, 0xB8, 0xC6, 0x03, 0x85, 0xC0, 0x75,
       0x19, 0x83, 0x7D, 0xFC, 0x04, 0x75, 0x13, 0x83, 0x7D, 0x08, 0x04, 0x75, 0x0D, 0x8B, 0x45, 0xF8,
       0x3B, 0x45, 0x14, 0x7C, 0x05, 0x3B, 0x45, 0x18, 0x7E, 0x03, 0x8B, 0x45, 0x10, 0x8B, 0xE5, 0x5D,
       0xC2, 0x14, 0x00, 0x8B, 0x84, 0x81, 0x7C, 0x01, 0x00, 0x00, 0x3E, 0x8B, 0x84, 0x85, 0x7C, 0x01,
       0x00, 0x00, 0xC7, 0x84, 0x80, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0x3E, 0xC7, 0x84,
       0x8D, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0x8B, 0x04, 0x24, 0xA1, 0x30, 0x41, 0xAB,
       0x00, 0x75, 0xF0, 0xB8, 0x00, 0x00, 0x00, 0x11, 0x8B, 0xC1, 0x89, 0x43, 0x0C, 0x90, 0xCC, 0xCC
    };

    //srand(time(0));
    //char sig_buffer[256];
    //for (size_t i = 0; i < 50; i++) {
    //    udx_gen_sig_rnd(data, sizeof(data), sig_buffer, sizeof(sig_buffer), 8 + rand() % 8);
    //    printf("%s\n", sig_buffer);
    //}


    ud_t ud_obj;

    memset(&ud_obj, 0, sizeof(ud_t));

    ud_init(&ud_obj);
    ud_set_input_buffer(&ud_obj, data, sizeof(data));
    ud_set_mode(&ud_obj, 32);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);
    ud_set_pc(&ud_obj, 0x012FAC60);
    while (ud_disassemble(&ud_obj)) {
        printf("0x%08llX(%d)\t%s\n", ud_insn_off(&ud_obj), ud_insn_len(&ud_obj), ud_insn_asm(&ud_obj));
        printf("\t\tRaw:\t%s\n", ud_insn_hex(&ud_obj));
        printf("\t\tSig(A):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_ALL));
        printf("\t\tSig(H):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_HIGH));
        printf("\t\tSig(M):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_MID));
        printf("\t\tSig(L):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_LOW));
        printf("\t\tSig(N):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_NONE));

        if (ud_obj.have_modrm) {
            printf("\t\tModR/M:\t0x%X(%d)\n", ud_obj.modrm, ud_obj.modrm_offset);
        }
        else {
            printf("\t\tModR/M:\tNONE\n");
        }
        if (ud_obj.have_sib) {
            printf("\t\tSIB:\t0x%X(%d)\n", ud_obj.sib, ud_obj.sib_offset);
        }
        else {
            printf("\t\tSIB:\tNONE\n");
        }
        if (ud_obj.have_disp) {
            printf("\t\tDISP:\t0x%llX(%d, %d)\n", ud_obj.disp, ud_obj.disp_offset, ud_obj.disp_size);
        }
        else {
            printf("\t\tDISP:\tNONE\n");
        }
        if (ud_obj.have_imm) {
            printf("\t\tIMM:\t0x%llX(%d, %d)\n", ud_obj.imm, ud_obj.imm_offset, ud_obj.imm_size);
        }
        else {
            printf("\t\tIMM:\tNONE\n");
        }
        printf("\t\tSTB:\t%d\n", ud_obj.modrm_stb);
        printf("\n");
    }

    return 0;
}