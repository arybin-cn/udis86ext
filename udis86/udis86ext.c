#include "udis86.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

uint64_t ud_abs(int64_t src) {
    int64_t const mask = src >> ((sizeof(int) * 8) - 1);
    return (src ^ mask) - mask;
}

const char* ud_insn_hex_sig(struct ud* u, enum ud_match_lvl match_lvl)
{
    uint8_t i, j;
    size_t insn_len;
    char* src_hex = (char*)u->insn_hexcode;
    ud_insn_hex(u);
    if (match_lvl == UD_MATCH_ALL) return src_hex;
    if (match_lvl == UD_MATCH_NONE) {
        insn_len = ud_insn_len(u);
        for (i = 0, j = 0; j < insn_len; i += 3, j++) {
            src_hex[i] = '?'; src_hex[i + 1] = '?';
        }
        return src_hex;
    }
    if (u->have_modrm) {
        if (match_lvl < UD_MATCH_MID || (match_lvl < UD_MATCH_HIGH && !u->modrm_stb)) {
            i = u->modrm_offset * 3;
            src_hex[i] = '?';
            src_hex[i + 1] = '?';
        }
    }
    if (u->have_sib && match_lvl < UD_MATCH_HIGH) {
        i = u->sib_offset * 3;
        src_hex[i] = '?';
        src_hex[i + 1] = '?';
    }
    if (u->have_disp) {
        if (ud_abs(u->disp) > u->match_disp_threshold || match_lvl < UD_MATCH_MID) {
            for (i = u->disp_offset * 3, j = 0; j < u->disp_size; i += 3, j++) {
                src_hex[i] = '?'; src_hex[i + 1] = '?';
            }
        }
    }
    if (u->have_imm) {
        if (ud_abs(u->imm) > u->match_imm_threshold || match_lvl < UD_MATCH_MID) {
            for (i = u->imm_offset * 3, j = 0; j < u->imm_size; i += 3, j++) {
                src_hex[i] = '?'; src_hex[i + 1] = '?';
            }
        }
    }

    return src_hex;
}


void udx_init(udx_t* udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base, uint8_t mode) {
    srand((size_t)time(0)); 
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
    size_t insn_size_readed = 0, insn_sig_size, sig_size = 0, insn_size = 5 + rand() % (15 + 1);
    const char* insn_sig;
    while (ud_disassemble(&udx->ud)) {
        insn_sig = ud_insn_hex_sig(&udx->ud, (ud_match_lvl_t)(rand() % UD_MATCH_ALL));
        insn_sig_size = strlen(insn_sig);
        if (insn_sig_size > sig_buffer_size) break;
        if (strcat_s(sig_buffer, sig_buffer_size, insn_sig)) break;
        sig_size += insn_sig_size;
        sig_buffer += insn_sig_size;
        sig_buffer_size -= insn_sig_size;
        if (++insn_size_readed >= insn_size) break;
    }
    return sig_size;
}

size_t udx_scan_sig(udx_t* udx, char* sig_buffer, size_t sig_buffer_size, size_t* ret_buffer, size_t ret_buffer_size) {
    uint16_t real_sig[128] = { 0 };
    uint8_t real_sig_size = 0;
    size_t i, ret_size = 0;

    if (sig_buffer_size / 3 > sizeof(real_sig) / sizeof(uint16_t)) return 0;

    for (i = 0; i < sig_buffer_size; i += 3) {
        while (sig_buffer[i] == ' ') i++;
        if (sig_buffer[i] == 0) break;
        if (sig_buffer[i] == '?') {
            real_sig[real_sig_size++] = SIG_WILDCARD;
        }
        else {
            sscanf_s(&sig_buffer[i], "%hx", &real_sig[real_sig_size++]);
        }
    } 
     
    uint8_t* start_addr = udx->mem_buffer;
    uint8_t* end_addr = start_addr + udx->mem_buffer_size - real_sig_size;

    while (start_addr < end_addr && ret_size < ret_buffer_size) {
        for (i = 0; i < real_sig_size; i++) {
            if (real_sig[i] == SIG_WILDCARD) continue;
            if (start_addr[i] != (uint8_t)real_sig[i]) break;
        }
        if (i >= real_sig_size) {
            ret_buffer[ret_size++] = (size_t)(start_addr - udx->mem_buffer + udx->load_base);
        }
        start_addr++;
    }

    return ret_size;
}