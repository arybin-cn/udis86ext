#include "udis86.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

void udx_init(udx_t *udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base ,uint8_t mode) {
    srand((size_t)time(0));
    memset(&udx->ud, 0, sizeof(ud_t));
    ud_init(&udx->ud);
    ud_set_mode(&udx->ud, mode);
    udx->load_base = load_base;
    udx->mem_buffer = mem_buffer;
    udx->mem_buffer_size = mem_buffer_size;
}

size_t udx_gen_sig(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size, enum ud_match_lvl match_lvl) {
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, target_addr - udx->load_base);
    ud_set_pc(&udx->ud, target_addr);
    memset(sig_buffer, 0, sig_buffer_size);
    size_t insn_size_readed = 0, insn_sig_size, sig_size = 0;
    const char* insn_sig;
    while (ud_disassemble(&udx->ud)) {
        insn_sig = ud_insn_hex_sig(&udx->ud, match_lvl);
        insn_sig_size = strlen(insn_sig);
        if (strcat_s(sig_buffer, sig_buffer_size, insn_sig)) return 0;
        sig_size += insn_sig_size;
        sig_buffer += insn_sig_size;
        sig_buffer_size -= insn_sig_size;
        if (++insn_size_readed >= insn_size) break;
    }
    return sig_size;
}

size_t udx_gen_sig_rnd(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size) {
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, target_addr - udx->load_base);
    ud_set_pc(&udx->ud, target_addr);
    memset(sig_buffer, 0, sig_buffer_size);
    size_t insn_size_readed = 0, insn_sig_size, sig_size = 0, insn_size = 4 + rand() % (4 + 1);
    const char* insn_sig;
    while (ud_disassemble(&udx->ud)) {
        insn_sig = ud_insn_hex_sig(&udx->ud, (ud_match_lvl_t)(rand() % UD_MATCH_ALL));
        insn_sig_size = strlen(insn_sig);
        if (strcat_s(sig_buffer, sig_buffer_size, insn_sig)) return 0;
        sig_size += insn_sig_size;
        sig_buffer += insn_sig_size;
        sig_buffer_size -= insn_sig_size;
        if (++insn_size_readed >= insn_size) break;
    }
    return sig_size;
}