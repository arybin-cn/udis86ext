#include "../udis86/udis86ext.h"

#include <string.h>
#include <time.h>
#include <stdlib.h> 

#define DUMP_FILE_FROM "..\\Res\\CMS168.1.CEM"
#define DUMP_FILE_TO "..\\Res\\CMS176.1.CEM"
#define TEST_COUNT 100

int main()
{ 
    srand((unsigned int)time(0));

    FILE* file;
    size_t file_size_old, file_size_new, file_size_readed;
    uint8_t* buffer_old, * buffer_new;

    fopen_s(&file, DUMP_FILE_FROM, "rb");
    fseek(file, 0, SEEK_END);
    file_size_old = ftell(file);
    printf("Old dump file size: %zd bytes\n", file_size_old);
    fseek(file, 0, SEEK_SET);
    buffer_old = (uint8_t*)malloc(file_size_old);
    file_size_readed = fread_s(buffer_old, file_size_old, 1, file_size_old, file);
    printf("Old dump file readed size: %zd bytes\n", file_size_readed);
    fclose(file);

    fopen_s(&file, DUMP_FILE_TO, "rb");
    fseek(file, 0, SEEK_END);
    file_size_new = ftell(file);
    printf("New dump file size: %zd bytes\n", file_size_new);
    fseek(file, 0, SEEK_SET);
    buffer_new = (uint8_t*)malloc(file_size_new);
    file_size_readed = fread_s(buffer_new, file_size_new, 1, file_size_new, file);
    printf("New dump file readed size: %zd bytes\n", file_size_readed);
    fclose(file);

    printf("Migrate from %s to %s\n", DUMP_FILE_FROM, DUMP_FILE_TO);

    udx_t udx_src;
    udx_init(&udx_src, buffer_old, file_size_old, 0x400000, 32);
    udx_t udx_dst;
    udx_init(&udx_dst, buffer_new, file_size_new, 0x400000, 32);


    for (size_t j = 0; j < 100; j++)
    {
        clock_t st = clock();
        udx_migrate_result_t mig_res;
        size_t src_addr = 0x401000 + (rand() * rand() % (udx_src.mem_buffer_size / 2 - 0x1000));
        //size_t src_addr = 0x1BF3764;
        src_addr = udx_insn_align(&udx_src, src_addr);
        size_t sample_cnt = 100;
        udx_migrate(&udx_src, &udx_dst, src_addr, &mig_res, 0x50, 0x100, sample_cnt);
        clock_t et = clock();
        double time_elapsed = (double)(et - st) / CLOCKS_PER_SEC;
        printf("\nMigrate for %08zX completed, %zd/%zd signatures hit %zd address(s), time elapsed: %.2fs\n\n",
            src_addr, mig_res.hit, mig_res.total, mig_res.mig_count, time_elapsed);
        for (size_t i = 0; i < mig_res.mig_count; i++)
        {
            udx_addr_t* mig_addr = mig_res.migs + i;
            printf("%2zd %08zX\thit: %3zd, stability: %6.2f%%, similarity: %6.2f%%, probability: %6.2f%%\n",
                i + 1, mig_addr->address, mig_addr->hit, mig_addr->stability, mig_addr->similarity, mig_addr->probability);
        }
        system("pause");
    }


    /*udx_sample_result_t sample_res;
    size_t cnt = 0;
    clock_t st = clock();
    for (size_t i = 0; i < 100; i++)
    {
        udx_sample(&udx_old, &udx_new, 0x114884A, &sample_res, 0x50, 0x100);
        if (sample_res.samples_count) {
            printf("\n(%zd) Sig of %s%zX hit %zd results, get %zd address(s) -> \n%s\n", ++cnt,
                (int32_t)(sample_res.addr_sig - sample_res.cached_addr_src) >= 0 ? "0x" : "-0x",
                udx_abs(sample_res.addr_sig - sample_res.cached_addr_src),
                sample_res.scan_result.addrs_count, sample_res.samples_count, sample_res.sig);
            for (size_t j = 0; j < sample_res.samples_count; j++)
            {
                printf("%08zX Stability: %.2f%%\n", sample_res.samples[j].address, sample_res.samples[j].stability);
            }
        }
    }
    clock_t et = clock();
    double time_elapsed = (double)(et - st) / CLOCKS_PER_SEC;
    printf("Time elapsed: %.2fs\n", time_elapsed); */

    //udx_sample(&udx_new, &udx_old, 0x1DE81CF, &sample_res);
    //udx_sample(&udx_new, &udx_old, 0x1DE81CF, &sample_res);


    //int32_t offsets[100];
    //size_t noffsets = udx_gen_offsets_radius(&udx_new, 0x1DE8206, offsets, sizeof(offsets), 3);
    //for (size_t i = 0; i < noffsets; i++)
    //{
    //    printf("(%zd) %X\n", i + 1, offsets[i]);
    //} 

    //udx_blk_t blks[100];
    //size_t nblks = udx_gen_blks_radius(&udx_new, 0x01DE8250, blks, sizeof(blks), 30);
    //for (size_t i = 0; i < nblks; i++)
    //{
    //    printf("(%d) %08zX\n", i + 1, blks[i].insn_addr);
    //}


    //size_t max_round_from = 100, max_round_to = 100;
    //size_t radius_from = 10, radius_to = 10;

    //for (size_t maxRound = max_round_from; maxRound <= max_round_from; maxRound++)
    //{
    //    for (size_t radius = radius_from; radius <= radius_to; radius++)
    //    {
    //        size_t succeed_count = 0;
    //        size_t failed_addr[TEST_COUNT];
    //        size_t failed_addr_size = 0;
    //        clock_t st = clock();
    //        for (size_t i = 0; i < TEST_COUNT; i++)
    //        {
    //            udx_blk_t* blks;
    //            size_t blks_length /*= udx_gen_blks(&udx_old, 0x401000 + (rand() * rand()) % (udx_old.mem_buffer_size / 2), &blks, 20, 0)*/;
    //            size_t src_addr = blks[blks_length - 2].insn_addr;
    //            udx_addr_t* res; 
    //            /*src_addr = 0x0894CFE;*/
    //            printf("Start migrating for %08zX\n", src_addr);
    //            size_t addrs_count /*= udx_migrate(&udx_old, &udx_new, src_addr, &res, radius, maxRound)*/;
    //            if (addrs_count) {
    //                succeed_count++;
    //                printf("Migrate for %08zX (%zd):\n", src_addr, addrs_count);
    //                for (size_t j = 0; j < addrs_count; j++)
    //                {
    //                    printf("(%.2zd)\tAddr: %08zX\tStability: %.2lf%%\tHit: %.2zd\tProb: %.2lf%%\n",
    //                        j + 1, res[j].address, res[j].stability, res[j].hit, res[j].prob);
    //                }
    //                /*system("pause");*/
    //                udx_free(res);
    //            }
    //            else {
    //                failed_addr[failed_addr_size++] = src_addr;
    //            }
    //            udx_free(blks);
    //            system("pause");
    //        }
    //        clock_t et = clock();
    //        double time_elapsed = (double)(et - st) / CLOCKS_PER_SEC / TEST_COUNT;
    //        printf("Radius: %.3zd, MaxRound:%.3zd, Average Time Elapsed: %.3fs, Migrate Rate: %.3f (%zd/%d)\nFailed address(%zd): ",
    //            radius, maxRound, time_elapsed, ((double)succeed_count) / TEST_COUNT, succeed_count, TEST_COUNT, failed_addr_size);
    //        for (size_t i = 0; i < failed_addr_size; i++)
    //        {
    //            printf("%08zX ", failed_addr[i]);
    //        }
    //        printf("\n");
    //    }
    //}


    free(buffer_old);
    free(buffer_new);


 /*   uint8_t data[] =
    {
        0x55, 0x8B, 0xEC, 0x53, 0x56, 0x57, 0xFF, 0x75, 0x08, 0x8B, 0xF9, 0xE8, 0xE0, 0x03, 0x00, 0x00,
        0x8B, 0x77, 0x04, 0x8B, 0xD8, 0x8B, 0x17, 0x2B, 0xF2, 0x56, 0x52, 0x53, 0xE8, 0x5F, 0xF7, 0x74,
        0x02, 0x8B, 0x0F, 0x83, 0xC4, 0x0C, 0x8B, 0x77, 0x04, 0x2B, 0xF1, 0xC1, 0xFE, 0x02, 0x85, 0xC9,
        0x74, 0x14, 0x8B, 0x47, 0x08, 0x2B, 0xC1, 0x6A, 0x04, 0xC1, 0xF8, 0x02, 0x50, 0x51, 0xE8, 0xDD,
        0xF9, 0xFF, 0xFF, 0x83, 0xC4, 0x0C, 0x8B, 0x45, 0x08, 0x8D, 0x04, 0x83, 0x89, 0x47, 0x08, 0x8D,
        0x04, 0xB3, 0x89, 0x47, 0x04, 0x89, 0x1F, 0x5F, 0x5E, 0x5B, 0x5D, 0xC2, 0x04, 0x00, 0xFF, 0x50,
        0x28
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