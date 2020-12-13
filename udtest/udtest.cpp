#include "../udis86/udis86.h"

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <cstdint>


extern "C" size_t udx_scan_sig(udx_t * udx, char* sig_buffer, size_t sig_buffer_size, size_t * ret_buffer, size_t ret_buffer_size);

int main()
{
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


    char sig[1024]; 
    size_t addrs[2000];
    size_t ret = 0;

    for (size_t j = 0; j < 100; j++)
    {
        size_t sig_size = udx_gen_sig_rnd(&udx_old, 0x1389C70, sig, sizeof(sig));
        printf("%s\n", sig);
        ret = udx_scan_sig(&udx_old, sig, sig_size, addrs, 2000);
        printf("%d results:\n", ret);
        ret = udx_scan_sig(&udx_new, sig, sig_size, addrs, 2000);
        printf("%d results:\n", ret); 
        //for (size_t i = 0; i < ret; i++)
        //{
        //    printf("(%d) %08X ", i + 1, addrs[i]);
        //}
        printf("\n**************************************************************************\n");
    }

    free(buffer_old);
    free(buffer_new);
 

  //  uint8_t data[] =
  //  {
  //0x8D, 0x42, 0x0C, 0x8B, 0x4A, 0xD8, 0x33, 0xC8, 0xE8, 0x96, 0x3D, 0xD8, 0xFF, 0xB8, 0x88, 0x38,
  //0x71, 0x03, 0xE9, 0x4F, 0xF0, 0xD9, 0xFF
  //  };

    //udx_t udx_old;
    //udx_init(&udx_old, data, sizeof(data), 0x012FAC60, 32);
    //char sig[100];
    //
    //for (size_t i = 0; i < 200; i++)
    //{
    //    udx_gen_sig_rnd(&udx_old, 0x012FAC60, sig, sizeof(sig));
    //    printf("%s\n", sig);

    //}

    //ud_t ud_obj;
    //ud_init(&ud_obj); 
    // 
    //ud_set_input_buffer(&ud_obj, data, sizeof(data));
    //ud_set_mode(&ud_obj, 32);
    //ud_set_syntax(&ud_obj, UD_SYN_INTEL);
    //ud_set_pc(&ud_obj, 0x02F37ABC);
    //while (ud_disassemble(&ud_obj)) {
    //    printf("0x%08llX(%d)\t%s\n", ud_insn_off(&ud_obj), ud_insn_len(&ud_obj), ud_insn_asm(&ud_obj));
    //    printf("\t\tRaw:\t%s\n", ud_insn_hex(&ud_obj));
    //    printf("\t\tSig(A):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_ALL));
    //    printf("\t\tSig(H):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_HIGH));
    //    printf("\t\tSig(M):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_MID));
    //    printf("\t\tSig(L):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_LOW));
    //    printf("\t\tSig(N):\t%s\n", ud_insn_hex_sig(&ud_obj, UD_MATCH_NONE));

    //    if (ud_obj.have_modrm) {
    //        printf("\t\tModR/M:\t0x%X(%d)\n", ud_obj.modrm, ud_obj.modrm_offset);
    //    }
    //    else {
    //        printf("\t\tModR/M:\tNONE\n");
    //    }
    //    if (ud_obj.have_sib) {
    //        printf("\t\tSIB:\t0x%X(%d)\n", ud_obj.sib, ud_obj.sib_offset);
    //    }
    //    else {
    //        printf("\t\tSIB:\tNONE\n");
    //    }
    //    if (ud_obj.have_disp) {
    //        printf("\t\tDISP:\t0x%llX(%d, %d)\n", ud_obj.disp, ud_obj.disp_offset, ud_obj.disp_size);
    //    }
    //    else {
    //        printf("\t\tDISP:\tNONE\n");
    //    }
    //    if (ud_obj.have_imm) {
    //        printf("\t\tIMM:\t0x%llX(%d, %d)\n", ud_obj.imm, ud_obj.imm_offset, ud_obj.imm_size);
    //    }
    //    else {
    //        printf("\t\tIMM:\tNONE\n");
    //    }
    //    printf("\t\tSTB:\t%d\n", ud_obj.modrm_stb);
    //    printf("\n");
    //}

    return 0;
}