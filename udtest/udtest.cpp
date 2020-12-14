#include "../udis86/udis86.h"

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <cstdint>
 
int main()
{
    srand((size_t)time(0));

    FILE* file;
    size_t file_size_old, file_size_new, file_size_readed;
    uint8_t* buffer_old, * buffer_new;

    fopen_s(&file, "..\\Res\\CMS176.1.CEM", "rb");
    fseek(file, 0, SEEK_END);
    file_size_old = ftell(file);
    printf("Old dump file size: %d bytes\n", file_size_old);
    fseek(file, 0, SEEK_SET);
    buffer_old = (uint8_t*)malloc(file_size_old);
    file_size_readed = fread_s(buffer_old, file_size_old, 1, file_size_old, file);
    printf("Old dump file readed size: %d bytes\n", file_size_readed);
    fclose(file);

    fopen_s(&file, "..\\Res\\CMS168.1.CEM", "rb");
    fseek(file, 0, SEEK_END);
    file_size_new = ftell(file);
    printf("New dump file size: %d bytes\n", file_size_new);
    fseek(file, 0, SEEK_SET);
    buffer_new = (uint8_t*)malloc(file_size_new);
    file_size_readed = fread_s(buffer_new, file_size_new, 1, file_size_new, file);
    printf("New dump file readed size: %d bytes\n", file_size_readed);
    fclose(file);

    udx_t udx_old;
    udx_init(&udx_old, buffer_old, file_size_old, 0x400000, 32);
    udx_t udx_new;
    udx_init(&udx_new, buffer_new, file_size_new, 0x400000, 32);


    char sig[2048]; 
    size_t addrs[256];
    size_t ret = 0;

    for (size_t j = 0; j < 100; j++)
    {
        size_t sig_size = udx_gen_sig_rnd(&udx_old, 0x1389C70, sig, sizeof(sig), udx_rnd(5, 30));
        printf("%s\n", sig);
        ret = udx_scan_sig(&udx_old, sig, sig_size, addrs, sizeof(addrs) / sizeof(size_t));
        printf("%d results:\n", ret);
        ret = udx_scan_sig(&udx_new, sig, sig_size, addrs, sizeof(addrs) / sizeof(size_t));
        printf("%d results:\n", ret); 
        //for (size_t i = 0; i < ret; i++)
        //{
        //    printf("(%d) %08X ", i + 1, addrs[i]);
        //}
        printf("\n**************************************************************************\n");
    }

    free(buffer_old);
    free(buffer_new);
 

    /*uint8_t data[] =
    {
        0x55, 0x8B, 0xEC, 0x53, 0x56, 0x57, 0xFF, 0x75, 0x08, 0x8B, 0xF9, 0xE8, 0xE0, 0x03, 0x00, 0x00,
        0x8B, 0x77, 0x04, 0x8B, 0xD8, 0x8B, 0x17, 0x2B, 0xF2, 0x56, 0x52, 0x53, 0xE8, 0x5F, 0xF7, 0x74,
        0x02, 0x8B, 0x0F, 0x83, 0xC4, 0x0C, 0x8B, 0x77, 0x04, 0x2B, 0xF1, 0xC1, 0xFE, 0x02, 0x85, 0xC9,
        0x74, 0x14, 0x8B, 0x47, 0x08, 0x2B, 0xC1, 0x6A, 0x04, 0xC1, 0xF8, 0x02, 0x50, 0x51, 0xE8, 0xDD,
        0xF9, 0xFF, 0xFF, 0x83, 0xC4, 0x0C, 0x8B, 0x45, 0x08, 0x8D, 0x04, 0x83, 0x89, 0x47, 0x08, 0x8D,
        0x04, 0xB3, 0x89, 0x47, 0x04, 0x89, 0x1F, 0x5F, 0x5E, 0x5B, 0x5D, 0xC2, 0x04, 0x00
    };
    char sig[1024];
    size_t sig_length = 0;

    ud_t ud_obj;
    ud_init(&ud_obj); 
     
    ud_set_input_buffer(&ud_obj, data, sizeof(data));
    ud_set_mode(&ud_obj, 32);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);
    ud_set_pc(&ud_obj, 0x400000);


    while (ud_disassemble(&ud_obj)) {
        printf("0x%08llX(%d)\t%s\n", ud_insn_off(&ud_obj), ud_insn_len(&ud_obj), ud_insn_asm(&ud_obj));
        printf("\t\tRaw:\t%s\n", ud_insn_hex(&ud_obj));
        ud_gen_sig(&ud_obj, sig, sizeof(sig), UD_MATCH_ALL);
        printf("\t\tSig(A):\t%s\n", sig);
        ud_gen_sig(&ud_obj, sig, sizeof(sig), UD_MATCH_HIGH);
        printf("\t\tSig(H):\t%s\n", sig);
        ud_gen_sig(&ud_obj, sig, sizeof(sig), UD_MATCH_MID);
        printf("\t\tSig(M):\t%s\n", sig);
        ud_gen_sig(&ud_obj, sig, sizeof(sig), UD_MATCH_LOW);
        printf("\t\tSig(L):\t%s\n", sig);
        ud_gen_sig(&ud_obj, sig, sizeof(sig), UD_MATCH_NONE);
        printf("\t\tSig(N):\t%s\n", sig);

        if (ud_obj.blk.have_modrm) {
            printf("\t\tModR/M:\t0x%X(%d)\n", ud_obj.blk.modrm, ud_obj.blk.modrm_offset);
        }
        else {
            printf("\t\tModR/M:\tNONE\n");
        }
        if (ud_obj.blk.have_sib) {
            printf("\t\tSIB:\t0x%X(%d)\n", ud_obj.blk.sib, ud_obj.blk.sib_offset);
        }
        else {
            printf("\t\tSIB:\tNONE\n");
        }
        if (ud_obj.blk.have_disp) {
            printf("\t\tDISP:\t0x%llX(%d, %d)\n", ud_obj.blk.disp, ud_obj.blk.disp_offset, ud_obj.blk.disp_size);
        }
        else {
            printf("\t\tDISP:\tNONE\n");
        }
        if (ud_obj.blk.have_imm) {
            printf("\t\tIMM:\t0x%llX(%d, %d)\n", ud_obj.blk.imm, ud_obj.blk.imm_offset, ud_obj.blk.imm_size);
        }
        else {
            printf("\t\tIMM:\tNONE\n");
        }
        printf("\t\tSTB:\t%d\n", ud_obj.blk.modrm_stb);
        printf("\n");
    }*/

    return 0;
}