#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// --- Estrutura para armazenar Labels ---
#define MAX_LABELS 100 // Número máximo de labels que o montador pode lidar
typedef struct {
    char name[50]; // Nome do label
    int address;   // Endereço (em bytes) do label
} Label;

Label labels[MAX_LABELS];
int label_count = 0;

// Função para adicionar um label à tabela
void add_label(const char *name, int address) {
    if (label_count < MAX_LABELS) {
        strcpy(labels[label_count].name, name);
        labels[label_count].address = address;
        label_count++;
    } else {
        fprintf(stderr, "Erro: Limite de labels excedido. Aumente MAX_LABELS.\n");
    }
}

// Função para buscar o endereço de um label
int find_label_address(const char *name) {
    for (int i = 0; i < label_count; i++) {
        if (strcmp(labels[i].name, name) == 0) {
            return labels[i].address;
        }
    }
    return -1; // Label não encontrado
}

// --- Funções Auxiliares ---
int get_register_number(const char *reg_name) {
    if (strcmp(reg_name, "zero") == 0) return 0;
    if (strcmp(reg_name, "ra") == 0) return 1;
    if (strcmp(reg_name, "sp") == 0) return 2;
    if (strcmp(reg_name, "gp") == 0) return 3;
    if (strcmp(reg_name, "tp") == 0) return 4;
    if (strcmp(reg_name, "t0") == 0) return 5;
    if (strcmp(reg_name, "t1") == 0) return 6;
    if (strcmp(reg_name, "t2") == 0) return 7;
    if (strcmp(reg_name, "s0") == 0 || strcmp(reg_name, "fp") == 0) return 8;
    if (strcmp(reg_name, "s1") == 0) return 9;
    if (strcmp(reg_name, "a0") == 0) return 10;
    if (strcmp(reg_name, "a1") == 0) return 11;
    if (strcmp(reg_name, "a2") == 0) return 12;
    if (strcmp(reg_name, "a3") == 0) return 13;
    if (strcmp(reg_name, "a4") == 0) return 14;
    if (strcmp(reg_name, "a5") == 0) return 15;
    if (strcmp(reg_name, "a6") == 0) return 16;
    if (strcmp(reg_name, "a7") == 0) return 17;
    if (strcmp(reg_name, "s2") == 0) return 18;
    if (strcmp(reg_name, "s3") == 0) return 19;
    if (strcmp(reg_name, "s4") == 0) return 20;
    if (strcmp(reg_name, "s5") == 0) return 21;
    if (strcmp(reg_name, "s6") == 0) return 22;
    if (strcmp(reg_name, "s7") == 0) return 23;
    if (strcmp(reg_name, "s8") == 0) return 24;
    if (strcmp(reg_name, "s9") == 0) return 25;
    if (strcmp(reg_name, "s10") == 0) return 26;
    if (strcmp(reg_name, "s11") == 0) return 27;
    if (strcmp(reg_name, "t3") == 0) return 28;
    if (strcmp(reg_name, "t4") == 0) return 29;
    if (strcmp(reg_name, "t5") == 0) return 30;
    if (strcmp(reg_name, "t6") == 0) return 31;
    
    if (reg_name[0] == 'x') {
        return atoi(&reg_name[1]);
    }
    return -1; // Erro
}

void dec_to_bin_n_bits(int n, int num, char *bin_str) {
    for (int i = n - 1; i >= 0; i--) {
        bin_str[n - 1 - i] = ((num >> i) & 1) ? '1' : '0';
    }
    bin_str[n] = '\0';
}

// --- Função da Primeira Passagem ---
void first_pass(const char *input_filename) {
    FILE *input_file = fopen(input_filename, "r");
    if (input_file == NULL) {
        perror("Erro ao abrir o arquivo de entrada na primeira passagem");
        exit(1);
    }

    char line[256];
    int current_address = 0;

    while (fgets(line, sizeof(line), input_file) != NULL) {
        // Ignora linhas vazias ou comentários
        if (strlen(line) <= 1 || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Remove quebra de linha e espaços em branco extras no final, se houver
        line[strcspn(line, "\r\n")] = 0;
        
        char temp_line[256];
        strcpy(temp_line, line);
        char *token = strtok(temp_line, " ,\t");
        if (token == NULL) continue;

        // Se a linha contém apenas espaços ou tabs após filtrar comentários, ignora
        int only_whitespace = 1;
        for(int i = 0; line[i] != '\0'; i++) {
            if (line[i] != ' ' && line[i] != '\t') {
                only_whitespace = 0;
                break;
            }
        }
        if (only_whitespace) continue;


        if (strchr(token, ':') != NULL) {
            token[strlen(token) - 1] = '\0';
            add_label(token, current_address);
            token = strtok(NULL, " ,\t");
            if (token == NULL) { // Se a linha só tinha o label
                continue; 
            }
        }
        current_address += 4; // Só incrementa se houver instrução
    }
    fclose(input_file);
}

// --- Função da Segunda Passagem ---
void second_pass(const char *input_filename, const char *output_filename) {
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    char line[256];
    int current_address = 0;
    int first_instruction_written = 1; // Flag para controlar a primeira escrita

    input_file = fopen(input_filename, "r");
    if (input_file == NULL) {
        perror("Erro ao abrir o arquivo de entrada na segunda passagem");
        return;
    }

    output_file = fopen(output_filename, "w");
    if (output_file == NULL) {
        perror("Erro ao abrir o arquivo de saída");
        fclose(input_file);
        return;
    }

    while (fgets(line, sizeof(line), input_file) != NULL) {
        char original_line[256]; // Salva a linha original para msgs de erro
        strcpy(original_line, line);
        original_line[strcspn(original_line, "\r\n")] = 0; // Limpa a original também

        if (strlen(line) <= 1 || line[0] == '#' || line[0] == ';') {
            continue;
        }
        line[strcspn(line, "\r\n")] = 0;
        char temp_line[256];
        strcpy(temp_line, line);
        char *token = strtok(temp_line, " ,\t");
        if (token == NULL) continue;
        
        // Verifica se a linha é apenas whitespace (novamente)
        int only_whitespace = 1;
        for(int i = 0; line[i] != '\0'; i++) {
            if (line[i] != ' ' && line[i] != '\t' && line[i] != ':') { // Permite ':' aqui
                char* check_label = strchr(line, ':');
                if (check_label && (strspn(check_label + 1, " \t") == strlen(check_label + 1))) {
                    // É um label seguido apenas de whitespace, ignora
                } else {
                   only_whitespace = 0;
                }
                break;
            }
        }
        if (only_whitespace) continue;

        char *instr = token;
        if (strchr(instr, ':') != NULL) {
            instr = strtok(NULL, " ,\t");
            if (instr == NULL) {
                continue;
            }
        }
        
        uint32_t instruction_binary = 0;
        int instruction_valid = 1;

        // --- Instruções tipo R ---
        if (strcmp(instr, "add") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *rs1_str = strtok(NULL, " ,\t"); char *rs2_str = strtok(NULL, " ,\t");
            if (!rd_str || !rs1_str || !rs2_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'add'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int rs2 = get_register_number(rs2_str);
            if (rd == -1 || rs1 == -1 || rs2 == -1) { fprintf(stderr, "Erro 0x%04X: Reg inválido 'add'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = (0b0000000 << 25) | (rs2 << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0b0110011; }
        } else if (strcmp(instr, "sub") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *rs1_str = strtok(NULL, " ,\t"); char *rs2_str = strtok(NULL, " ,\t");
            if (!rd_str || !rs1_str || !rs2_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'sub'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int rs2 = get_register_number(rs2_str);
            if (rd == -1 || rs1 == -1 || rs2 == -1) { fprintf(stderr, "Erro 0x%04X: Reg inválido 'sub'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = (0b0100000 << 25) | (rs2 << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0b0110011; }
        } else if (strcmp(instr, "xor") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *rs1_str = strtok(NULL, " ,\t"); char *rs2_str = strtok(NULL, " ,\t");
            if (!rd_str || !rs1_str || !rs2_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'xor'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int rs2 = get_register_number(rs2_str);
            if (rd == -1 || rs1 == -1 || rs2 == -1) { fprintf(stderr, "Erro 0x%04X: Reg inválido 'xor'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = (0b0000000 << 25) | (rs2 << 20) | (rs1 << 15) | (0b100 << 12) | (rd << 7) | 0b0110011; }
        } else if (strcmp(instr, "or") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *rs1_str = strtok(NULL, " ,\t"); char *rs2_str = strtok(NULL, " ,\t");
            if (!rd_str || !rs1_str || !rs2_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'or'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int rs2 = get_register_number(rs2_str);
            if (rd == -1 || rs1 == -1 || rs2 == -1) { fprintf(stderr, "Erro 0x%04X: Reg inválido 'or'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = (0b0000000 << 25) | (rs2 << 20) | (rs1 << 15) | (0b110 << 12) | (rd << 7) | 0b0110011; }
        } else if (strcmp(instr, "and") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *rs1_str = strtok(NULL, " ,\t"); char *rs2_str = strtok(NULL, " ,\t");
            if (!rd_str || !rs1_str || !rs2_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'and'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int rs2 = get_register_number(rs2_str);
            if (rd == -1 || rs1 == -1 || rs2 == -1) { fprintf(stderr, "Erro 0x%04X: Reg inválido 'and'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = (0b0000000 << 25) | (rs2 << 20) | (rs1 << 15) | (0b111 << 12) | (rd << 7) | 0b0110011; }
        } else if (strcmp(instr, "slli") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *rs1_str = strtok(NULL, " ,\t"); char *shamt_str = strtok(NULL, " ,\t");
            if (!rd_str || !rs1_str || !shamt_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'slli'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int shamt = atoi(shamt_str);
            if (rd == -1 || rs1 == -1 || shamt < 0 || shamt >= 32) { fprintf(stderr, "Erro 0x%04X: Param inválido 'slli'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = (0b0000000 << 25) | (shamt << 20) | (rs1 << 15) | (0b001 << 12) | (rd << 7) | 0b0010011; }
        } else if (strcmp(instr, "srli") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *rs1_str = strtok(NULL, " ,\t"); char *shamt_str = strtok(NULL, " ,\t");
            if (!rd_str || !rs1_str || !shamt_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'srli'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int shamt = atoi(shamt_str);
            if (rd == -1 || rs1 == -1 || shamt < 0 || shamt >= 32) { fprintf(stderr, "Erro 0x%04X: Param inválido 'srli'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = (0b0000000 << 25) | (shamt << 20) | (rs1 << 15) | (0b101 << 12) | (rd << 7) | 0b0010011; }

        // --- Instruções tipo I ---
        } else if (strcmp(instr, "addi") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *rs1_str = strtok(NULL, " ,\t"); char *imm_str = strtok(NULL, " ,\t");
            if (!rd_str || !rs1_str || !imm_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'addi'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int imm = atoi(imm_str);
            if (rd == -1 || rs1 == -1 || imm < -2048 || imm > 2047) { fprintf(stderr, "Erro 0x%04X: Param inválido 'addi'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = ((imm & 0xFFF) << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0b0010011; }
        } else if (strcmp(instr, "lw") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *offset_rs1_str = strtok(NULL, " ,\t");
            if (!rd_str || !offset_rs1_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'lw'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { char *offset_str = strtok(offset_rs1_str, "("); char *rs1_str = strtok(NULL, ")");
            if (offset_str == NULL || rs1_str == NULL) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'lw'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int offset = atoi(offset_str);
            if (rd == -1 || rs1 == -1 || offset < -2048 || offset > 2047) { fprintf(stderr, "Erro 0x%04X: Param inválido 'lw'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = ((offset & 0xFFF) << 20) | (rs1 << 15) | (0b010 << 12) | (rd << 7) | 0b0000011; } }

        // --- Instruções tipo S ---
        } else if (strcmp(instr, "sw") == 0) {
            char *rs2_str = strtok(NULL, " ,\t"); char *offset_rs1_str = strtok(NULL, " ,\t");
            if (!rs2_str || !offset_rs1_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'sw'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { char *offset_str = strtok(offset_rs1_str, "("); char *rs1_str = strtok(NULL, ")");
            if (offset_str == NULL || rs1_str == NULL) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'sw'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rs2 = get_register_number(rs2_str); int rs1 = get_register_number(rs1_str); int offset = atoi(offset_str);
            if (rs2 == -1 || rs1 == -1 || offset < -2048 || offset > 2047) { fprintf(stderr, "Erro 0x%04X: Param inválido 'sw'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { uint32_t imm_11_5 = (offset >> 5) & 0x7F; uint32_t imm_4_0 = offset & 0x1F;
            instruction_binary = (imm_11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (0b010 << 12) | (imm_4_0 << 7) | 0b0100011; } } }

        // --- Instruções tipo B ---
        } else if (strcmp(instr, "beq") == 0 || strcmp(instr, "bne") == 0) {
            char *rs1_str = strtok(NULL, " ,\t"); char *rs2_str = strtok(NULL, " ,\t"); char *target_label = strtok(NULL, " ,\t");
            if (rs1_str == NULL || rs2_str == NULL || target_label == NULL) { fprintf(stderr, "Erro 0x%04X: Formato inválido '%s'. Linha: %s\n", current_address, instr, original_line); instruction_valid = 0; }
            else { int rs1 = get_register_number(rs1_str); int rs2 = get_register_number(rs2_str); int target_address = find_label_address(target_label);
            if (rs1 == -1 || rs2 == -1) { fprintf(stderr, "Erro 0x%04X: Reg inválido '%s'. Linha: %s\n", current_address, instr, original_line); instruction_valid = 0; }
            else if (target_address == -1) { fprintf(stderr, "Erro 0x%04X: Label '%s' não encontrado. Linha: %s\n", current_address, target_label, original_line); instruction_valid = 0; }
            else { int offset = target_address - current_address;  
            if (offset % 2 != 0) { fprintf(stderr, "Erro 0x%04X: Offset branch '%s' não é par. Linha: %s\n", current_address, target_label, original_line); instruction_valid = 0; }
            else { offset = offset / 2; 
            if (offset < -2048 || offset > 2047) { fprintf(stderr, "Erro 0x%04X: Offset branch '%s' fora de alcance. Linha: %s\n", current_address, target_label, original_line); instruction_valid = 0;}
            else { uint32_t imm_12 = (offset >> 11) & 0x1; uint32_t imm_10_5 = (offset >> 4) & 0x3F; uint32_t imm_4_1 = offset & 0xF; uint32_t imm_11 = (offset >> 10) & 0x1;
            if (strcmp(instr, "beq") == 0) { instruction_binary = (imm_12 << 31) | (imm_10_5 << 25) | (rs2 << 20) | (rs1 << 15) | (0b000 << 12) | (imm_4_1 << 8) | (imm_11 << 7) | 0b1100011; } 
            else { instruction_binary = (imm_12 << 31) | (imm_10_5 << 25) | (rs2 << 20) | (rs1 << 15) | (0b001 << 12) | (imm_4_1 << 8) | (imm_11 << 7) | 0b1100011; } } } } }

        // --- Instruções tipo U ---
        } else if (strcmp(instr, "lui") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *imm_str = strtok(NULL, " ,\t");
            if (rd_str == NULL || imm_str == NULL) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'lui'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int imm = strtol(imm_str, NULL, 0);
            if (rd == -1) { fprintf(stderr, "Erro 0x%04X: Reg inválido 'lui'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = ((imm & 0xFFFFF) << 12) | (rd << 7) | 0b0110111; }

        // --- Instruções tipo J (jal) ---
        } else if (strcmp(instr, "jal") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *target_label = strtok(NULL, " ,\t");
            if (rd_str == NULL || target_label == NULL) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'jal'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int target_address = find_label_address(target_label);
            if (rd == -1) { fprintf(stderr, "Erro 0x%04X: Reg inválido 'jal'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else if (target_address == -1) { fprintf(stderr, "Erro 0x%04X: Label '%s' não encontrado. Linha: %s\n", current_address, target_label, original_line); instruction_valid = 0; }
            else { int offset = target_address - current_address;
            if (offset % 2 != 0) { fprintf(stderr, "Erro 0x%04X: Offset JAL '%s' não é par. Linha: %s\n", current_address, target_label, original_line); instruction_valid = 0; }
            else { offset = offset / 2;
            if (offset < -(1 << 19) || offset >= (1 << 19) ) { fprintf(stderr, "Erro 0x%04X: Offset JAL '%s' fora de alcance. Linha: %s\n", current_address, target_label, original_line); instruction_valid = 0; }
            else { uint32_t imm20 = (offset >> 19) & 0x1; uint32_t imm10_1 = (offset >> 0) & 0x3FF; uint32_t imm11 = (offset >> 10) & 0x1; uint32_t imm19_12 = (offset >> 11) & 0xFF;
            instruction_binary = (imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12) | (rd << 7) | 0b1101111; } } } }

        // --- Instruções tipo I (jalr) ---
        } else if (strcmp(instr, "jalr") == 0) {
            char *rd_str = strtok(NULL, " ,\t"); char *next_token = strtok(NULL, " ,\t");
            if (!rd_str || !next_token) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'jalr'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { char *rs1_str; char *offset_str; char *parenOpen = strchr(next_token, '(');
            if (parenOpen) { offset_str = strtok(next_token, "("); rs1_str = strtok(NULL, ")"); } 
            else { offset_str = "0"; rs1_str = next_token; }
            if (!rs1_str) { fprintf(stderr, "Erro 0x%04X: Formato inválido 'jalr'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else { int rd = get_register_number(rd_str); int rs1 = get_register_number(rs1_str); int offset = atoi(offset_str);
            if (rd == -1 || rs1 == -1 || offset < -2048 || offset > 2047) { fprintf(stderr, "Erro 0x%04X: Param inválido 'jalr'. Linha: %s\n", current_address, original_line); instruction_valid = 0; }
            else instruction_binary = ((offset & 0xFFF) << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0b1100111; } }

        } else {
            fprintf(stderr, "Instrução desconhecida 0x%04X: '%s'. Linha: %s\n", current_address, instr, original_line);
            instruction_valid = 0;
        }

        if (instruction_valid) {
             if (!first_instruction_written) {
                fprintf(output_file, "\n"); // Adiciona newline ANTES da próxima instrução
            } else {
                first_instruction_written = 0; // Marca que a primeira já foi escrita
            }

            char byte_binary_str[9];
            uint8_t byte0 = (instruction_binary >> 0) & 0xFF;
            uint8_t byte1 = (instruction_binary >> 8) & 0xFF;
            uint8_t byte2 = (instruction_binary >> 16) & 0xFF;
            uint8_t byte3 = (instruction_binary >> 24) & 0xFF;

            dec_to_bin_n_bits(8, byte0, byte_binary_str);
            fprintf(output_file, "%s", byte_binary_str); // Byte 0

            dec_to_bin_n_bits(8, byte1, byte_binary_str);
            fprintf(output_file, "\n%s", byte_binary_str); // Byte 1

            dec_to_bin_n_bits(8, byte2, byte_binary_str);
            fprintf(output_file, "\n%s", byte_binary_str); // Byte 2

            dec_to_bin_n_bits(8, byte3, byte_binary_str);
            fprintf(output_file, "\n%s", byte_binary_str); // Byte 3 (Sem \n aqui)
            
            current_address += 4;
        }
    }

    fclose(input_file);
    fclose(output_file);
    printf("Montagem concluída! Arquivo '%s' gerado.\n", output_filename);
}

int main(int argc, char *argv[]) {
    const char *input_filename;
    const char *output_filename;

    // Verifica os argumentos da linha de comando
    if (argc == 2) {
        input_filename = argv[1];
        output_filename = "memoria.mif"; // Nome padrão
    } else if (argc == 3) {
        input_filename = argv[1];
        output_filename = argv[2]; // Nome fornecido
    } else {
        fprintf(stderr, "Uso: %s <arquivo_entrada.asm> [arquivo_saida.mif]\n", argv[0]);
        return 1; // Retorna erro
    }

    // Print input file name and content
    printf("%s:\n", input_filename);
    FILE *asm_file_for_print = fopen(input_filename, "r");
    if (asm_file_for_print == NULL) {
        perror("Erro ao abrir arquivo de entrada para leitura inicial");
        return 1; 
    }
    char line_buffer[256];
    int last_char = EOF; // Para verificar se o arquivo termina com \n
    while (fgets(line_buffer, sizeof(line_buffer), asm_file_for_print)) {
        fputs(line_buffer, stdout);
        last_char = line_buffer[strlen(line_buffer)-1];
    }
    fclose(asm_file_for_print);
    // Garante uma nova linha após o conteúdo do asm, se necessário.
    if (last_char != '\n' && last_char != EOF) {
        printf("\n");
    }
    printf("\n"); // Adiciona uma linha extra para separar do output

    // First Pass: Coleta labels
    first_pass(input_filename);

    // Second Pass: Monta o código e resolve labels
    second_pass(input_filename, output_filename);

    // Print output file name and content
    printf("\n%s:\n", output_filename); 
    FILE *mif_file_for_print = fopen(output_filename, "r");
    if (mif_file_for_print == NULL) {
        fprintf(stderr, "Aviso: Não foi possível abrir '%s' para ler seu conteúdo.\n", output_filename);
    } else {
        char mif_line_buffer[32]; 
        while (fgets(mif_line_buffer, sizeof(mif_line_buffer), mif_file_for_print)) {
            fputs(mif_line_buffer, stdout);
        }
        fclose(mif_file_for_print);
        // Adiciona uma nova linha no final do *print* para o prompt não grudar
        printf("\n");
    }

    return 0;
}