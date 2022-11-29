#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable(char *argv)
{
  char buffer[15];
  strcpy(buffer, argv);
}

int main(int argc, char *argv[])
{
  /*
   * N.B. If you pass argv[] into vulnerable() directly, you don't get
   *      the exact disassembly as the provided binary. argv[1] is needed.
   *      The asm code that tells me this is seen below.
   *      Note that it's in AT&T syntax: i.e. src, dst
   *      0x00000000000011e9 <+23>:	add    $0x8,%rax
   *      0x00000000000011ed <+27>:	mov    (%rax),%rax
   *      Meaning that there's a "shift" to point to the next "index" of the array.
   *      You can try to edit the code to see it yourself.
   *
   *      build the code using: gcc -g cs5231-RE-target.c
   *      if you use "gcc -g -no-pie cs5231-RE-target.c" instead
   *      you will see fixed addresses for functions
   *      -no-pie = don't produce dynamically linked position independent variables
   */ 

  vulnerable(argv[1]);
  printf("Return properly!\n");
  return 0;
}
