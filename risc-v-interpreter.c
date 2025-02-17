#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <math.h>


typedef enum { false, true } bool;


typedef struct{
    char name[7];
    uint32_t rs1;
    uint32_t rs2;
    uint32_t rd;
} TypeR;

typedef struct {
    char name[7];
    uint32_t rs1;
    uint32_t imm;
    uint32_t rd;
} TypeI;

typedef struct{
    char name[7];
    uint32_t rs1;
    uint32_t rs2;
    uint32_t imm;
} TypeS;

typedef struct{
    char name[7];
    uint32_t rs1;
    uint32_t rs2;
    int32_t imm;
} TypeSB;

typedef struct{
    char name[7];
    uint32_t rd;
    uint32_t imm;
} TypeU;

typedef struct{
    char name[7];
    uint32_t rd;
    uint32_t imm;
} TypeUJ;

union structure{
    TypeR instruction_type_R;
    TypeI instruction_type_I;
    TypeS instruction_type_S;
    TypeSB instruction_type_SB;
    TypeUJ instruction_type_UJ;
    TypeU instruction_type_U;
};


typedef struct{
    uint32_t start_position_in_memory;
} Heap_storage;


#define NUMBER_OF_BANKS 128 // 128 banks need to be stored
#define MAX_INSTRUCTION_SIZE sizeof(TypeS) // biggest struct is set as size for no overflows


int32_t sign_extend(int32_t input, int first_bit) {
    if (input & (1 << (first_bit - 1))) {
        //extend the sign by setting all bits to the left of the first bit to 1
        int32_t left_ones = 0b11111111111111111111111111111111; // holds 1's 32 of them for worst case
        int32_t sign_extension_mask = (left_ones << first_bit); // shifts left by first bit amout of times ,so the mask is only 1's on the left
        return (input | sign_extension_mask); // makes all the mask 1's i.e. left of the bit 1's
    } else {
        return input;
    }
}


union structure* parsef(uint32_t bits_read){ // parse binary input
    int type = 0;
    uint32_t mask = 0b1111111;
    uint32_t opcodes = bits_read & mask; // mask to get last 7 digits, as & operator preserves bits in mask and wipes else

    if (opcodes == 0b0010011){ // type I
        type = 1;
    } else if(opcodes == 0b0110011){ // type R
        type = 2;
    } else if (opcodes == 0b0110111){ // type U
        type = 3;
    } else if (opcodes == 0b0100011){ // type S
        type = 4;
    } else if (opcodes == 0b1100011) { // type SB
        type = 5;
    } else if (opcodes == 0b1101111) { // type UJ
        type = 6;
    } else if (opcodes == 0b0000011) { // type I v2
        type = 7;
    } else if (opcodes == 0b1100111) { // type I v3
        type = 8;
    } else {
        printf("\nno valid opcode\n");
        return NULL;
    }

    uint32_t rd;
    uint32_t func3;
    uint32_t rs1;
    uint32_t rs2;
    uint32_t func7;
    int32_t imm1;
    int32_t imm2;
    int32_t imm_final;

    switch(type){
        case 1: // case I
            union structure* instructionI = malloc(MAX_INSTRUCTION_SIZE); // initialse a instruction union
    
            mask = 0b111;
            func3 = (bits_read >> 12) & mask;
           
            if (func3 == 0b000){
                //addi
                strcpy(instructionI->instruction_type_I.name, "addi");
                
            } else if (func3 == 0b010){
                // slti
                strcpy(instructionI->instruction_type_I.name, "slti");

            } else if (func3 == 0b011){
                // sltiu
                strcpy(instructionI->instruction_type_I.name, "sltiu");

            } else if (func3 == 0b100) {
                //xori
                strcpy(instructionI->instruction_type_I.name, "xori");

            } else if (func3 == 0b110){
                // ori
                strcpy(instructionI->instruction_type_I.name, "ori");

            } else if (func3 == 0b111){
                // andi
                strcpy(instructionI->instruction_type_I.name, "andi");

            } else {
                printf("not recognised?\n");
                return NULL;
            }

            mask = 0b11111;
            rd = (bits_read >> 7) & mask; // shift right adds x 0's on right, doesnt cycle round
            instructionI->instruction_type_I.rd = rd; 
      
            rs1 = (bits_read >> 15) & mask;
            instructionI->instruction_type_I.rs1 = rs1;        

            mask = 0b111111111111;
            imm1 = (bits_read >> 20) & mask;

            imm1 = sign_extend(imm1, 12); // sign extend as can be -

            instructionI->instruction_type_I.imm = imm1;
            
            return instructionI;
            break;

        case 2:
            union structure* instructionR = malloc(MAX_INSTRUCTION_SIZE);

            mask = 0b111;
            func3 = (bits_read >> 12) & mask;

            mask = 0b1111111;
            func7 = (bits_read >> 25) & mask;

            if ((func3 == 0b000) & (func7 == 0b0000000)) {
                // add
                strcpy(instructionR->instruction_type_R.name, "add");

            } else if ((func3 == 0b000) & (func7 == 0b0100000)){
                //sub
                strcpy(instructionR->instruction_type_R.name, "sub");

            } else if ((func3 == 0b100) & (func7 == 0b0000000)){
                // xor
                strcpy(instructionR->instruction_type_R.name, "xor");

            } else if ((func3 == 0b110) & (func7 == 0b0000000)){
                // or
                strcpy(instructionR->instruction_type_R.name, "or");

            } else if ((func3 == 0b111) & (func7 == 0b0000000)){
                // and
                strcpy(instructionR->instruction_type_R.name, "and");

            } else if ((func3 == 0b001) & (func7 == 0b0000000)){
                // sll
                strcpy(instructionR->instruction_type_R.name, "sll");

            } else if ((func3 == 0b101) & (func7 == 0b0000000)){
                // srl
                strcpy(instructionR->instruction_type_R.name, "srl");

            } else if ((func3 == 0b101) & (func7 == 0b0100000)){
                // sra
                strcpy(instructionR->instruction_type_R.name, "sra");

            } else if ((func3 == 0b010) & (func7 == 0b0000000)){
                // slt
                strcpy(instructionR->instruction_type_R.name, "slt");

            } else if ((func3 == 0b011) & (func7 == 0b0000000)){
                //sltu
                strcpy(instructionR->instruction_type_R.name, "sltu");

            } else {
                printf("not recognised?\n");
                return NULL;
            }
            mask = 0b11111;
            rd = (bits_read >> 7) & mask; 
            instructionR->instruction_type_R.rd = rd;
            

            rs1 = (bits_read >> 15) & mask;
            instructionR->instruction_type_R.rs1 = rs1;
           

            rs2 = (bits_read >> 20) & mask;
            instructionR->instruction_type_R.rs2 = rs2;
            
            return instructionR;

            break;
        case 3: // case for u
            union structure* instructionU = malloc(MAX_INSTRUCTION_SIZE);
            
            strcpy(instructionU->instruction_type_U.name, "lui");
            mask = 0b11111;
            rd = (bits_read >> 7) & mask;

            instructionU->instruction_type_U.rd = rd;
            
            uint32_t imm = ((bits_read >> 12) & 0b111111111111111111111);
           
            imm = sign_extend(imm, 12);

            instructionU->instruction_type_U.imm = imm;
          
            return instructionU;

            break;
        case 4: //case for s
            union structure* instructionS = malloc(MAX_INSTRUCTION_SIZE);

            mask = 0b111;
            func3 = (bits_read >> 12) & mask;

            if (func3 == 0b000){
                // sb
                strcpy(instructionS->instruction_type_S.name, "sb");

            } else if (func3 == 0b001){
                // sh
                strcpy(instructionS->instruction_type_S.name, "sh");

            } else if (func3 == 0b010){
                // sw
                strcpy(instructionS->instruction_type_S.name, "sw");

            } else {
                printf("not recognised?\n");
                return NULL;
            }
            mask = 0b11111;

            rs1 = (bits_read >> 15) & mask;
            instructionS->instruction_type_S.rs1 = rs1;
            
            rs2 = (bits_read >> 20) & mask;
            instructionS->instruction_type_S.rs2 = rs2;
            
            imm1 = (bits_read >> 7) & 0b11111; // extract bits 7-11 of the instruction
            imm2 = (bits_read >> 25) & 0b1111111; // extract bits 25-31 of the instruction
            int32_t temp = (imm2 << 5) | imm1; // adds 0's on right 
            int32_t imm_t = sign_extend(temp, 12);
            instructionS->instruction_type_S.imm = imm_t;
            
            return instructionS;
            
            break;

        case 5: //case for sb
            union structure* instructionSB = malloc(MAX_INSTRUCTION_SIZE);
            mask = 0b111;
            func3 = (bits_read >> 12) & mask;

            if (func3 == 0b000){
                // beq
                strcpy(instructionSB->instruction_type_SB.name, "beq");

            } else if (func3 == 0b001){
                // bne
                strcpy(instructionSB->instruction_type_SB.name, "bne");

            } else if (func3 == 0b100){
                // blt
                strcpy(instructionSB->instruction_type_SB.name, "blt");

            } else if (func3 == 0b110){
                // bltu
                strcpy(instructionSB->instruction_type_SB.name, "bltu");

            } else if (func3 == 0b101){
                // bge
                strcpy(instructionSB->instruction_type_SB.name, "bge");

            } else if (func3 == 0b111){
                // bgeu
                strcpy(instructionSB->instruction_type_SB.name, "bgeu");

            } else {
                printf("not recognised?\n");
                return NULL;
            }

            mask = 0b11111;
            rs1 = (bits_read >> 15) & mask;
            instructionSB->instruction_type_SB.rs1 = rs1;

            rs2 = (bits_read >> 20) & mask;
            instructionSB->instruction_type_SB.rs2 = rs2;
            
            int32_t imm_signed = (((bits_read >> 31) & 0b1) << 11) | (((bits_read >> 7) & 0b1) << 10) 
                                | (((bits_read >> 25) & 0b111111) << 4) | ((bits_read >> 8) & 0b1111);
                                // shift left adds x 0's on the left of a variable, doesnt cycle round
            imm_signed = (imm_signed << 1) | 0b0;
          
            imm_signed = sign_extend(imm_signed, 12);
            
            instructionSB->instruction_type_SB.imm = imm_signed;
            return instructionSB;
            break;

        case 6: //case for uj

            union structure* instructionUJ = malloc(MAX_INSTRUCTION_SIZE);
            strcpy(instructionUJ->instruction_type_UJ.name, "jal");
            mask = 0b11111;
            rd = (bits_read >> 7) & mask;
            instructionUJ->instruction_type_UJ.rd = rd;

            imm_final = ((bits_read >> 21) & 0b1111111111) | (((bits_read >> 20) & 0b1) << 10) |
                         (((bits_read >> 12) & 0b11111111) << 11) | (((bits_read >> 31) & 0b1) << 19);
          
            imm_final = (imm_final << 1) | 0b0;

            imm_final = sign_extend(imm_final, 20); 
            instructionUJ->instruction_type_UJ.imm = imm_final;

            return instructionUJ;
            
            break;
        case 7: // I v2
            union structure*instructionI2 = malloc(MAX_INSTRUCTION_SIZE);

            mask = 0b111;
            func3 = (bits_read >> 12) & mask;

            if (func3 == 0b000){
                // lb
                strcpy(instructionI2->instruction_type_I.name, "lb");

            } else if (func3 == 0b001){
                // lh
                strcpy(instructionI2->instruction_type_I.name, "lh");

            } else if (func3 == 0b010){
                // lw
                strcpy(instructionI2->instruction_type_I.name, "lw");

            } else if (func3 == 0b100){
                // lbu
                strcpy(instructionI2->instruction_type_I.name, "lbu");

            } else if (func3 == 0b101){
                // lhu
                strcpy(instructionI2->instruction_type_I.name, "lhu");

            } else {
                printf("not recognised?\n");
                return NULL;
            }
            mask = 0b11111;
            rd = (bits_read >> 7) & mask; 
            
            instructionI2->instruction_type_I.rd = rd;

            rs1 = (bits_read >> 15) & mask;
            instructionI2->instruction_type_I.rs1 = rs1;

            mask = 0b11111111111;
            imm1 = (bits_read >> 20) & mask;
            imm1 = sign_extend(imm1, 20); 
            instructionI2->instruction_type_I.imm = imm1;
        
            return instructionI2;
            break;
        case 8: // I v3 type
            union structure* instructionI3 = malloc(MAX_INSTRUCTION_SIZE);

            mask = 0b111;
            func3 = (bits_read >> 12) & mask;
            
            if (func3 == 0b000){
                // jarl
                strcpy(instructionI3->instruction_type_I.name, "jalr");
                mask = 0b11111;
                rd = (bits_read >> 7) & mask; 
                
                instructionI3->instruction_type_I.rd = rd;

                rs1 = (bits_read >> 15) & mask;
                instructionI3->instruction_type_I.rs1 = rs1;

                mask = 0b111111111111; 
                imm1 = (bits_read >> 20) & mask;
                imm1 = sign_extend(imm1, 12); 
                instructionI3->instruction_type_I.imm = imm1;

                return instructionI3;
            } else {
                printf("not recognised?\n");
                return NULL;
            }
            break;
        default:
            printf("not recognised?\n");
            return NULL;
            break;
    }
    return NULL;
}


void dump_registers(uint32_t R[32], int program_counter){
    printf("PC = 0x%x\n", program_counter);
    for (int i = 0; i < 32; i++){
        printf("R[%d] = 0x%x;\n", i, R[i]);
        R[i] = 0;
    }
}


char* compare_virtual_routines(uint32_t address){ // returns virtual array as char
    if (address == 0x0800){
        // console write char
        return "console write char";
    } else if (address == 0x0804){
        // write signed integer
        return "console write signed integer";
    } else if (address == 0x0808){
        // write unsigned integer
        return "console write unsigned integer";
    } else if (address == 0x080C){
        // HALT
        return "halt";
    } else if (address == 0x0812){
        // console read character
        return "read character";
    } else if (address == 0x0816){
        // Console Read Signed Intege
        return "Console Read Signed Integer";
    } else if (address == 0x0820){
        // dump PC
        return "dump register banks";
    } else if (address == 0x0824){
        // dump memory BANKS
        return "dump memory banks";
    } else if (address == 0x0828){
        // dump memory word
        return "dump memory word";
    } else if (address == 0x0830){
        return "malloc";
    } else if (address == 0x834){
        // heap bank
        return "free";
    } else if (address >= 0x0850){
        // reserved return reserverd
        return "reserved";
    }
    return "no match";
}



void save_byte(uint8_t thing_to_place, uint32_t address, uint32_t program_binary[512]){

    int line_to_store = address/4; // always rounded down
    int byte_place_to_store = address%4;
    
    if (line_to_store < 256){
        printf("written to instruction memory incorrectly\n");
        exit(1);
    }
    if (line_to_store > 512){
        printf("written outside of memeory\n");
        exit(1);
    }
    
    uint32_t line = program_binary[line_to_store];
    uint32_t mask = 0b11111111; 
 
    if (byte_place_to_store == 0){
        line &= ~mask; // removes first mask bits, ~ is not operator
        line |= thing_to_place;
    } else if (byte_place_to_store == 1){
        line &= ~(mask << 8);
        line |= (thing_to_place << 8);
    } else if (byte_place_to_store == 2){
        line &= ~(mask << 16);
        line |= (thing_to_place << 16);
    } else if (byte_place_to_store == 3){
        line &= ~(mask << 24);
        line |= (thing_to_place << 24);
    }

    program_binary[line_to_store] = line;
}


uint32_t get_byte(uint32_t placement, uint32_t program_binary[512]){
    int line_to_read = placement/4; // always rounded down
    int byte_to_read = placement%4;
   
    uint32_t return_byte = 0b0;
    uint32_t line = program_binary[line_to_read];
    uint32_t mask = 0b11111111; 

    if (byte_to_read == 0){
        return_byte = (line) & mask;
    } else if (byte_to_read == 1){
        return_byte = (line >> 8) & mask;
    } else if (byte_to_read == 2){
        return_byte = (line >> 16) & mask;
    } else if (byte_to_read == 3){
        return_byte = (line >> 24) & mask;
    }

    return return_byte;
}

int main(int argc, char **argv){

    uint32_t program_binary[512];
    FILE *fpointer = fopen(argv[1],"rb");
    uint32_t bits;

    if (!fpointer) {
        printf("file failed to open");
        return(1);
    } else {
        int instruction_place_counter = 0;
        while (fread(&bits, sizeof(uint32_t), 1, fpointer) == 1){ // reads whole line
            program_binary[instruction_place_counter] = bits;
            instruction_place_counter++;
        }
    }
    fclose(fpointer);

    int program_counter = 0;
    union structure *curr_instruction;
    char current_instruction_name[10];
    
    
    uint32_t R[32]; // initialise int_32_t regegister
    memset(R, 0, sizeof(R));

    uint32_t address;
    int32_t register_to_save;

    uint32_t variable_for_virtual_routine;
    int32_t byte;
    char virtual_routine_checker[40];

    Heap_storage Heap_map[NUMBER_OF_BANKS];
    memset(Heap_map, 0, sizeof(Heap_map));
    uint8_t Heap_memory[64*128];
    memset(Heap_memory, 0, sizeof(Heap_memory));
    
    while (true){
        if ((program_counter % 4) != 0){
            printf("Program counter incorrect\n");
            dump_registers(R, program_counter);
            exit(1);
        }

        printf("\nprogram counter: %d\n", program_counter);

        R[0] = 0;
        curr_instruction = NULL;
        strcpy(virtual_routine_checker,"nothing");
        
        curr_instruction = parsef(program_binary[program_counter/4]);
        strcpy(virtual_routine_checker,"baseline");
        variable_for_virtual_routine = 0;
        
        
        if (curr_instruction == NULL) {
            free(curr_instruction);
            printf("Current instruction invalid\n");
            dump_registers(R, program_counter);
            exit(1);
        }
        
        if (strcmp(curr_instruction->instruction_type_I.name, "addi") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "xori") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "slti") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "sltiu") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "ori") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "andi") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "jalr") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "lb") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "lh") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "lw") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "lbu") == 0 ||
                strcmp(curr_instruction->instruction_type_I.name, "lhu") == 0) {
            
            strcpy(current_instruction_name, curr_instruction->instruction_type_I.name);

        }  else if (strcmp(curr_instruction->instruction_type_R.name, "add") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "sub") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "xor") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "or") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "and") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "sll") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "srl") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "sra") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "slt") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "sltu") == 0) {
            
            strcpy(current_instruction_name, curr_instruction->instruction_type_R.name);
            
        } else if (strcmp(curr_instruction->instruction_type_R.name, "jal") == 0){
            strcpy(current_instruction_name, curr_instruction->instruction_type_UJ.name);
            
        } else if (strcmp(curr_instruction->instruction_type_R.name, "lui") == 0){
            strcpy(current_instruction_name, curr_instruction->instruction_type_U.name);

        } else if (strcmp(curr_instruction->instruction_type_R.name, "sb") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "sh") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "sw") == 0){

            strcpy(current_instruction_name, curr_instruction->instruction_type_S.name);

        } else if (strcmp(curr_instruction->instruction_type_R.name, "bne") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "blt") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "bltu") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "beq") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "bge") == 0 ||
                    strcmp(curr_instruction->instruction_type_R.name, "bgeu") == 0){
            
            strcpy(current_instruction_name, curr_instruction->instruction_type_SB.name);
        }

        printf("current instructinon: %s\n", current_instruction_name);

        if (strcmp(current_instruction_name, "addi") == 0) {
            R[curr_instruction->instruction_type_I.rd] = R[curr_instruction->instruction_type_I.rs1] + curr_instruction->instruction_type_I.imm;

        } else if (strcmp(current_instruction_name, "jal") == 0) {
            R[curr_instruction->instruction_type_UJ.rd] = program_counter+4;
            program_counter = (program_counter + (curr_instruction->instruction_type_UJ.imm)) - 4;
    
        } else if (strcmp(current_instruction_name, "lui") == 0) {
            R[curr_instruction->instruction_type_U.rd] = curr_instruction->instruction_type_U.imm << 12;

        } else if (strcmp(current_instruction_name, "sb") == 0) {
            address = R[curr_instruction->instruction_type_S.rs1] + curr_instruction->instruction_type_S.imm;
            variable_for_virtual_routine = R[curr_instruction->instruction_type_S.rs2];
            strcpy(virtual_routine_checker, compare_virtual_routines(address));

            if ((strcmp(virtual_routine_checker, "no match") == 0)){
                save_byte(variable_for_virtual_routine,address, program_binary);
            }
    
        } else if (strcmp(current_instruction_name, "jalr") == 0) {
            R[curr_instruction->instruction_type_I.rd] = program_counter + 4;
            program_counter = R[curr_instruction->instruction_type_I.rs1] + curr_instruction->instruction_type_I.imm - 4;
        
        } else if (strcmp(current_instruction_name, "sw") == 0) {
          
            variable_for_virtual_routine = R[curr_instruction->instruction_type_S.rs2];
            address = R[curr_instruction->instruction_type_S.rs1] + curr_instruction->instruction_type_S.imm;

            strcpy(virtual_routine_checker, compare_virtual_routines(address));
           
            if ((strcmp(virtual_routine_checker, "no match") == 0)){

                for (int i = 0; i < 4; i++){
                    uint8_t byte_to_save = (variable_for_virtual_routine >> (i*8)) & 0b11111111; // extract one byte from signed_number_to_print
                    save_byte(byte_to_save, address + i, program_binary);
                }
            }

        } else if (strcmp(current_instruction_name, "lw") == 0) {
            register_to_save = curr_instruction->instruction_type_I.rd;
            address = R[curr_instruction->instruction_type_I.rs1] + curr_instruction->instruction_type_I.imm;
            
            strcpy(virtual_routine_checker, compare_virtual_routines(address));

            if ((strcmp(virtual_routine_checker, "no match") == 0)){
                
                uint32_t byte = 0;
                uint32_t final_byte = 0;
                for (int i = 0; i < 4; i++){
                     byte = get_byte(address+i,program_binary);
                     final_byte |= byte << (8*i);

                }
                R[curr_instruction->instruction_type_I.rd] = final_byte;   
            }
           
        } else if (strcmp(current_instruction_name, "add") == 0) {

            R[curr_instruction->instruction_type_R.rd] = R[curr_instruction->instruction_type_R.rs1] + R[curr_instruction->instruction_type_R.rs2];

        } else if (strcmp(current_instruction_name, "beq") == 0) {
           
            if (R[curr_instruction->instruction_type_SB.rs1] == R[curr_instruction->instruction_type_SB.rs2]){
                program_counter = program_counter + curr_instruction->instruction_type_SB.imm - 4;
            }
        
        } else if (strcmp(current_instruction_name, "bne") == 0) {
            
            if (R[curr_instruction->instruction_type_SB.rs1] != R[curr_instruction->instruction_type_SB.rs2]){
                program_counter = program_counter + curr_instruction->instruction_type_SB.imm - 4;
            }
            
        } else if (strcmp(current_instruction_name, "lbu") == 0) {
           
            byte = get_byte(R[curr_instruction->instruction_type_I.rs1] + curr_instruction->instruction_type_I.imm, program_binary);
            
            R[curr_instruction->instruction_type_I.rd] = byte;
           
        } else if (strcmp(current_instruction_name, "sll") == 0) {
            R[curr_instruction->instruction_type_R.rd] = R[curr_instruction->instruction_type_R.rs1] << R[curr_instruction->instruction_type_R.rs2];

        } else if (strcmp(current_instruction_name, "srl") == 0) {
             R[curr_instruction->instruction_type_R.rd] = R[curr_instruction->instruction_type_R.rs1] >> R[curr_instruction->instruction_type_R.rs2];

        } else if (strcmp(current_instruction_name, "bge") == 0) {
            if (R[curr_instruction->instruction_type_SB.rs1] >= R[curr_instruction->instruction_type_SB.rs2]){
                program_counter = program_counter + curr_instruction->instruction_type_SB.imm - 4;
            }
        } else if (strcmp(current_instruction_name, "andi") == 0) {
            R[curr_instruction->instruction_type_I.rd] = R[curr_instruction->instruction_type_I.rs1] & curr_instruction->instruction_type_I.imm;

        } else if (strcmp(current_instruction_name, "xor") == 0) {
            R[curr_instruction->instruction_type_I.rd] = R[curr_instruction->instruction_type_I.rs1] ^ curr_instruction->instruction_type_I.imm;

        } else if (strcmp(current_instruction_name, "or") == 0) {
            R[curr_instruction->instruction_type_R.rd] = R[curr_instruction->instruction_type_R.rs1] | R[curr_instruction->instruction_type_R.rs2];

        } else if (strcmp(current_instruction_name, "and") == 0) {
            R[curr_instruction->instruction_type_R.rd] = R[curr_instruction->instruction_type_R.rs1] & R[curr_instruction->instruction_type_R.rs2];

        } else if (strcmp(current_instruction_name, "blt") == 0) {
            if (R[curr_instruction->instruction_type_SB.rs1] <= R[curr_instruction->instruction_type_SB.rs2]){
                program_counter = program_counter + curr_instruction->instruction_type_SB.imm - 4;
            }

        } else if (strcmp(current_instruction_name, "sub") == 0) {
            R[curr_instruction->instruction_type_R.rd] = R[curr_instruction->instruction_type_R.rs1] - R[curr_instruction->instruction_type_R.rs2];

        } else {
            printf("current instruction:%s\n",current_instruction_name);
            printf("not implemented yet\n");
            dump_registers(R, program_counter);
            free(curr_instruction);
            exit(1);
            // Code to handle an unrecognized/unimplemented instruction name
        }

        if ((strcmp(virtual_routine_checker, "console write char") == 0)){
            printf("%c",(char) variable_for_virtual_routine);

        } else if (strcmp(virtual_routine_checker, "console write signed integer") == 0){ 
            printf("%d",variable_for_virtual_routine);

        } else if (strcmp(virtual_routine_checker, "console write unsigned integer") == 0){
            printf("%x", variable_for_virtual_routine);

        } else if (strcmp(virtual_routine_checker, "halt") == 0){
            free(curr_instruction);
            printf("CPU Halt Requested\n");
            exit(0);

        } else if (strcmp(virtual_routine_checker, "read character") == 0){
            // console read character
            
        } else if (strcmp(virtual_routine_checker, "dump pc") == 0){
            // dump PC

        } else if (strcmp(virtual_routine_checker, "Console Read Signed Integer") == 0){

            int number_read;
            scanf("%d", &number_read);
            R[register_to_save] = number_read;

        } else if (strcmp(virtual_routine_checker, "dump memory word") == 0){
            // dump memory word

        } else if (strcmp(virtual_routine_checker, "malloc") == 0){
            
            if (variable_for_virtual_routine > UINT32_MAX){ 
                R[28] = 0;
            } else {
                    
                    int banks_needed = (int) ceil(((float)variable_for_virtual_routine)/64);// float to ensure decimals r used otherwise wont round then cast back to int
                   
                    if(banks_needed == 0){
                        R[28] = 0;
                    }
                    int saves_start = 0;
                    bool is_space = false;
                    
                    bool correct_found = false;
                    
                    for (int i = 0; i <= NUMBER_OF_BANKS - banks_needed; i++){ 
                        if (Heap_map[i].start_position_in_memory == 0){
                            saves_start = i;
                            for (int j = 0; j < banks_needed; j++){
                                if (i+j >= NUMBER_OF_BANKS){
                                    break;
                                }
                                if (Heap_map[i+j].start_position_in_memory == 0){
                                    if (j == banks_needed - 1){
                                        is_space = true;
                                        correct_found = true;
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                        if (correct_found == true){
                            break;
                        }
                    }
                    
                    if (is_space == false || correct_found == false){
                        R[28] = 0;
                    } else {

                        bool error = false;
                        for (int k = saves_start; k < saves_start + banks_needed; k++){
                            if (k >= NUMBER_OF_BANKS) {
                                R[28] = 0;
                                error = true;
                                break;
                            }
                            Heap_map[k].start_position_in_memory = 0xb700 + saves_start;
                        }
                        if (error != true){
                            for (int j = saves_start*64; j < (banks_needed*64); j++){
                                Heap_memory[j] = variable_for_virtual_routine;
                            }

                            R[28] = 0xb700 + saves_start*64;
                        }
                        
                    }
            }

        } else if (strcmp(virtual_routine_checker, "free") == 0){

            for (int i = 0; i < NUMBER_OF_BANKS; i++){
                if (variable_for_virtual_routine/64 - 0xb700 == Heap_map[i].start_position_in_memory){
                    for (int j = Heap_map[i].start_position_in_memory; j < NUMBER_OF_BANKS - Heap_map[i].start_position_in_memory;j++){
                        Heap_map[j].start_position_in_memory = 0;
                    }
                }
            }

        } else if (strcmp(virtual_routine_checker, "reserved") == 0){
            // reserved

        } else if (strcmp(virtual_routine_checker, "dump register banks") == 0){
            // dump register banks
        }

         for (int i = 0; i < 32; i++){
            if (R[i] != 0){
                printf("unsigned R%d = %u\n", i, R[i]);
            }
        }
        printf("\n");


        free(curr_instruction);
        program_counter+= 4;
    }
    return 0;
}