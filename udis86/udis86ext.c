#include <stdlib.h>
#include <string.h>

#include "udis86.h" 

uint64_t udx_abs(int64_t src) {
    int64_t const mask = src >> ((sizeof(int) * 8) - 1);
    return (src ^ mask) - mask;
}

size_t udx_rnd(size_t a, size_t b) {
    return a + (rand() % (b - a + 1));
}

void udx_init(udx_t* udx, uint8_t* mem_buffer, size_t mem_buffer_size, size_t load_base, uint8_t mode) {
    ud_init(&udx->ud);
    ud_set_mode(&udx->ud, mode);
    udx->load_base = load_base;
    udx->mem_buffer = mem_buffer;
    udx->mem_buffer_size = mem_buffer_size;
}

size_t udx_blk_gen_sig(struct udx_blk* blk, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl)
{
    uint8_t i, j;
    char* origin_sig_buffer = sig_buffer; 
    size_t sig_length = 0;
     
    for (i = 0; i < blk->insn_length; i++) {
        if (sig_buffer_size < 3 + 1) return 0;
        sprintf_s(sig_buffer, sig_buffer_size, "%02X ", blk->insn_bytes[i]);
        sig_buffer += 3;
        sig_buffer_size -= 3;
    } 
    sig_length = sig_buffer - origin_sig_buffer;
    sig_buffer = origin_sig_buffer;
    
    if (match_lvl == UD_MATCH_ALL) return sig_length;
    if (match_lvl == UD_MATCH_NONE) {
        for (i = 0, j = 0; j < blk->insn_length; i += 3, j++) {
            sig_buffer[i] = '?'; sig_buffer[i + 1] = '?';
        }
        return sig_length;
    }
    if (blk->have_modrm) {
        if (match_lvl < UD_MATCH_MID || (match_lvl < UD_MATCH_HIGH && !blk->modrm_stb)) {
            i = blk->modrm_offset * 3;
            sig_buffer[i] = '?';
            sig_buffer[i + 1] = '?';
        }
    }
    if (blk->have_sib && match_lvl < UD_MATCH_HIGH) {
        i = blk->sib_offset * 3;
        sig_buffer[i] = '?';
        sig_buffer[i + 1] = '?';
    }
    if (blk->have_disp) {
        if (udx_abs(blk->disp) > disp_threshold || match_lvl < UD_MATCH_MID) {
            for (i = blk->disp_offset * 3, j = 0; j < blk->disp_size; i += 3, j++) {
                sig_buffer[i] = '?'; sig_buffer[i + 1] = '?';
            }
        }
    }
    if (blk->have_imm) {
        if (udx_abs(blk->imm) > imm_threshold || match_lvl < UD_MATCH_MID) {
            for (i = blk->imm_offset * 3, j = 0; j < blk->imm_size; i += 3, j++) {
                sig_buffer[i] = '?'; sig_buffer[i + 1] = '?';
            }
        }
    }

    return sig_length;
}

size_t udx_blks_gen_sig(struct udx_blk* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold, size_t match_lvl)
{
    size_t sig_length = 0, blk_sig_length;
    for (size_t i = 0; i < blks_size; i++) {
        blk_sig_length = udx_blk_gen_sig(blks + i, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, match_lvl);
        if (!blk_sig_length) return 0;
        sig_buffer += blk_sig_length;
        sig_buffer_size -= blk_sig_length;
        sig_length += blk_sig_length;
    }
    return sig_length;
     
}

size_t udx_blks_gen_sig_rnd(struct udx_blk* blks, size_t blks_size, char* sig_buffer, size_t sig_buffer_size, size_t disp_threshold, size_t imm_threshold)
{
    size_t insns_size = blks_size / sizeof(struct udx_blk);
    size_t sig_length = 0, blk_sig_length;
    for (size_t i = 0; i < insns_size; i++) {
        blk_sig_length = udx_blk_gen_sig(blks + i, sig_buffer, sig_buffer_size, disp_threshold, imm_threshold, udx_rnd(UD_MATCH_NONE, UD_MATCH_HIGH));
        if (!blk_sig_length) return 0;
        sig_buffer += blk_sig_length;
        sig_buffer_size -= blk_sig_length;
        sig_length += blk_sig_length;
    }
    return sig_length;

}

size_t udx_gen_sig(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size, size_t match_lvl) {
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, target_addr - udx->load_base);
    ud_set_pc(&udx->ud, target_addr);
    size_t insn_sig_size, sig_size = 0, insn_size_readed = 0;
    while (ud_disassemble(&udx->ud)) {
        insn_sig_size = ud_gen_sig(&udx->ud, sig_buffer, sig_buffer_size, match_lvl);
        if (!insn_sig_size) return 0;
        sig_buffer += insn_sig_size;
        sig_buffer_size -= insn_sig_size;
        sig_size += insn_sig_size;
        if (++insn_size_readed >= insn_size) break;
    }
    return sig_size;
}

size_t udx_gen_sig_rnd(udx_t* udx, size_t target_addr, char* sig_buffer, size_t sig_buffer_size, size_t insn_size) {
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, target_addr - udx->load_base);
    ud_set_pc(&udx->ud, target_addr);

    size_t insn_sig_size, sig_size = 0, insn_size_readed = 0;
    while (ud_disassemble(&udx->ud)) {
        insn_sig_size = ud_gen_sig(&udx->ud, sig_buffer, sig_buffer_size, udx_rnd(UD_MATCH_NONE, UD_MATCH_HIGH));
        if (!insn_sig_size) return 0;
        sig_buffer += insn_sig_size;
        sig_buffer_size -= insn_sig_size;
        sig_size += insn_sig_size;
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

size_t udx_gen_blks(udx_t* udx, size_t target_addr, struct udx_blk* blks_buffer, size_t blks_size) {
    size_t insns_size = blks_size / sizeof(struct udx_blk), blks_size_generated = 0;
    ud_set_input_buffer(&udx->ud, udx->mem_buffer, udx->mem_buffer_size);
    ud_input_skip(&udx->ud, target_addr - udx->load_base);
    ud_set_pc(&udx->ud, target_addr);
    while (ud_disassemble(&udx->ud)) {
        if (insns_size-- <= 0) break;
        memcpy_s(blks_buffer++, sizeof(struct udx_blk), &udx->ud.blk, sizeof(struct udx_blk));
        blks_size_generated++;
    } 
    return blks_size_generated;
}


size_t ud_gen_sig(struct ud* u, char* sig_buffer, size_t sig_buffer_size, size_t match_lvl)
{
    return udx_blk_gen_sig(&u->blk, sig_buffer, sig_buffer_size, DEF_THRESHOLD_DISP, DEF_THRESHOLD_IMM, match_lvl);
}