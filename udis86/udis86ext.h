#pragma once
#include "udis86.h"
#include "../uthash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ARYBIN 0x46724672

#define UD_MATCH_NONE 0
#define UD_MATCH_LOW 1
#define UD_MATCH_MID 2
#define UD_MATCH_HIGH 3
#define UD_MATCH_ALL 4

#define SIG_WILDCARD 0xFFFF

#define DEF_THRESHOLD_DISP 0x50
#define DEF_THRESHOLD_IMM 0x100

#define RES_DISTANCE_DIMENSION 128
#define RES_PROB_MIN 50.0 //%

#define RND_SIG_INSNS_SIZE_MIN 5
#define RND_SIG_INSNS_SIZE_MAX 15

#define EXTRA_INSN_RADIUS 16
#define AVERAGE_INSN_LENGTH 7
#define AVERAGE_DISTANCE_BETWEEN_CALLS 30

typedef struct {
    uint8_t mode;
    uint8_t* mem_buffer;
    size_t mem_buffer_size;
    size_t load_base;
}udx_t;

#define SCAN_RES_SIZE 8192-3
typedef struct {
    size_t addrs_count;
    size_t addrs[SCAN_RES_SIZE];
    size_t mark_index;
    udx_t* udx;
}udx_scan_result_t;

typedef struct {
    size_t address;
    size_t hit;
    float similarity;
    float prob;
}udx_addr_t;

typedef struct {
    size_t address;
    size_t hit;
    float similarity;
    UT_hash_handle hh;
}udx_hashed_addr_t;

void udx_init(udx_t* udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base, uint8_t mode);

size_t udx_init_ud(udx_t* udx, ud_t* ud, size_t address);

void udx_free(void* ptr);

int8_t udx_byte(udx_t* udx, size_t address);

int16_t udx_word(udx_t* udx, size_t address);

int32_t udx_dword(udx_t* udx, size_t address);

int64_t udx_qword(udx_t* udx, size_t address);

uint64_t udx_abs(int64_t src);

size_t udx_rnd(size_t a, size_t b);

size_t udx_blk_gen_sig(udx_blk_t* blk, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl);

size_t udx_blks_gen_sig(udx_blk_t* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl);

size_t udx_blks_gen_sig_rnd(udx_blk_t* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold);

size_t udx_gen_offsets(udx_t* udx, size_t target_addr, int32_t* offsets_buffer, size_t offsets_buffer_size, size_t count, size_t skip_count);

size_t udx_gen_sig(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size, size_t match_lvl);

size_t udx_gen_sig_rnd(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size);

size_t udx_scan_sig(udx_t* udx, char* sig_buffer, size_t sig_buffer_size, udx_scan_result_t* result, size_t mark_addr);

size_t udx_gen_addr(size_t address, float similarity, udx_addr_t** paddr);

size_t udx_gen_hashed_addr(size_t address, float similarity, udx_hashed_addr_t** paddr);

size_t udx_migrate_scan_result(udx_scan_result_t* res_src, udx_scan_result_t* res_dst, udx_addr_t** paddrs);

size_t udx_gen_blks(udx_t* udx, size_t target_addr, udx_blk_t** pblks, size_t insns_count, size_t skip_count);

size_t udx_gen_blks_radius(udx_t* udx, size_t target_addr, udx_blk_t** pblks, size_t insns_count_radius);

size_t udx_insn_count(udx_t* udx, size_t start_addr, size_t end_addr);

ud_mnemonic_code_t udx_insn_mnemonic(udx_t* udx, size_t addr);

size_t udx_migrate(udx_t* udx_src, udx_t* udx_dst, size_t src_addr, udx_addr_t** paddrs, size_t sample_radius, size_t sample_count, size_t* total_sample_count);

size_t ud_gen_sig(ud_t* u, char* sig_buffer, size_t sig_buffer_size, size_t match_lvl);

#ifdef __cplusplus
}
#endif