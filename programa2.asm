addi a0, zero, 6
add t1, a0, zero
sub t2, t1, a0
loop: beq t2, zero, fim
jal zero, loop
fim: nop
