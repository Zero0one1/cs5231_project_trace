#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable(char *argv)
{
  char a1[20]="hello world";
  char buffer[10];
  printf("%s", a1);
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
   *      build the code using: gcc -g -fstack-protector -Wl,-z,relro,-z,now -o test_two_strcpy test_two_strcpy.c
   */ 

  vulnerable(argv[1]);
  printf("Return properly!\n");
  return 0;
}