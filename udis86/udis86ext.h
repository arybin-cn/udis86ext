#pragma once
#include "udis86.h"
#include "../uthash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ARYBIN 0x46724672
#define BOOL uint8_t
#define UD_Iall UD_MAX_MNEMONIC_CODE

#define UD_MATCH_NONE 0
#define UD_MATCH_LOW 1
#define UD_MATCH_MID 2
#define UD_MATCH_HIGH 3
#define UD_MATCH_ALL 4

#define DEF_THRESHOLD_DISP 0x50
#define DEF_THRESHOLD_IMM 0x100

#define OFFSETS_DIMENSION 64
#define RES_PROB_MIN 30.0 //%

#define PROBE_INSN_COUNT 32
#define AVERAGE_INSN_LENGTH 7


typedef struct {
    uint8_t mode;
    uint8_t* mem_buffer;
    size_t mem_buffer_size;
    size_t load_base;
}udx_t;

#define SCAN_RES_SIZE 1024*8-3
typedef struct {
    size_t addrs_count;
    size_t addrs[SCAN_RES_SIZE];
    udx_t* udx;
}udx_scan_result_t;

typedef struct {
    size_t address;
    size_t hit;
    float stability;
    UT_hash_handle hh;
}udx_hashed_addr_t;

typedef struct {
    size_t address;
    size_t hit;
    float stability;
    float similarity; //reduce by @hit, @total
    float probability; //reduce by @hit, @stability, @similarity
}udx_addr_t;

#define SAMPLE_RES_SIZE 4
#define SAMPLE_SIG_INSN_CNT_MIN 3
#define SAMPLE_SIG_INSN_CNT_MAX 10
#define SAMPLE_SIG_SIZE (SAMPLE_SIG_INSN_CNT_MAX*AVERAGE_INSN_LENGTH*3)
typedef struct {
    size_t cached_addr_src;
    size_t cached_addr_src_aligned;
    udx_blk_t cached_blks[SAMPLE_SIG_INSN_CNT_MAX * 2 + 1];

    size_t samples_count;
    udx_addr_t samples[SAMPLE_RES_SIZE];
    size_t addr_sig;
    char sig[SAMPLE_SIG_SIZE];
    udx_scan_result_t scan_result;
}udx_sample_result_t;

#define MIGRATE_RES_SIZE 128
typedef struct {
    size_t mig_count;
    udx_addr_t migs[MIGRATE_RES_SIZE];
    size_t hit;
    size_t total;
}udx_migrate_result_t;

void udx_init(udx_t* udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base, uint8_t mode);

size_t udx_init_ud(udx_t* udx, ud_t* ud, size_t address);

//void udx_free(void* ptr);

int8_t udx_byte(udx_t* udx, size_t address);

int16_t udx_word(udx_t* udx, size_t address);

int32_t udx_dword(udx_t* udx, size_t address);

int64_t udx_qword(udx_t* udx, size_t address);

size_t udx_abs(intptr_t src);

size_t udx_rnd(size_t a, size_t b);

size_t ud_gen_sig(ud_t* u, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl);

size_t udx_gen_sig(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t insn_size, size_t match_lvl);

size_t udx_gen_sig_blk(udx_blk_t* blk, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl);

size_t udx_gen_sig_blks(udx_blk_t* blks, size_t insn_cnt, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl);

size_t udx_gen_sig_blks_rnd(udx_blk_t* blks, size_t insn_cnt, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold);

size_t udx_gen_offsets(udx_t* udx, size_t target_addr, int32_t* offsets_buffer, size_t offsets_buffer_size, size_t count);

size_t udx_gen_offsets_radius(udx_t* udx, size_t target_addr, int32_t* offsets_buffer, size_t offsets_buffer_size, size_t radius);

size_t udx_scan_sig(udx_t* udx, char* sig, udx_scan_result_t* result);

size_t udx_gen_addr(size_t address, float stability, udx_addr_t* addr);

size_t udx_gen_hashed_addr(size_t address, float stability, udx_hashed_addr_t* addr);

size_t udx_migrate_scan_result(udx_t* udx_src, size_t addr_src, size_t addr_src_origin, udx_scan_result_t* res_dst, udx_addr_t* addrs_buffer, size_t addrs_buffer_size);

size_t udx_gen_blks(udx_t* udx, size_t target_addr, udx_blk_t* blks_buffer, size_t blks_buffer_size, size_t insn_cnt);

size_t udx_gen_blks_radius(udx_t* udx, size_t target_addr, udx_blk_t* blks_buffer, size_t blks_buffer_size, size_t radius);

size_t udx_insn_count(udx_t* udx, size_t start_addr, size_t end_addr, ud_mnemonic_code_t mnemonic);

size_t udx_insn_align(udx_t* udx, size_t target_addr);

size_t udx_insn_reverse_of(udx_t* udx, size_t end_addr, size_t reversed_insn_count, ud_mnemonic_code_t mnemonic);

size_t udx_insn_reverse(udx_t* udx, size_t end_addr, size_t reversed_insn_count);

size_t udx_insn_search(udx_t* udx, size_t target_addr, ud_mnemonic_code_t mnemonic, int32_t direction);

ud_mnemonic_code_t udx_insn_mnemonic(udx_t* udx, size_t addr);

size_t udx_sample(udx_t* udx_src, udx_t* udx_dst, size_t addr_src, udx_sample_result_t* sample_res, size_t disp_threshold, size_t imm_threshold);

size_t udx_migrate(udx_t* udx_src, udx_t* udx_dst, size_t addr_src, udx_migrate_result_t* mig_res, size_t disp_threshold, size_t imm_threshold, size_t sample_cnt);

//size_t udx_migrate(udx_t* udx_src, udx_t* udx_dst, size_t src_addr, udx_addr_t** paddrs, size_t sample_radius, size_t sample_count);

#ifdef __cplusplus
}
#endif