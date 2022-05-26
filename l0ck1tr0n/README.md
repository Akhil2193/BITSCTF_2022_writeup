# l0ck1tr0n

  

There are two files to analyze, one is the l0ck file and second is the seed. Through the ```file``` command, we can see l0ck is an ELF binary executable and seed is zip file. So on running the l0ck file, we can see a lock, probably this is same lock that the challenge is asking us to open. On extracting the zip file contents we can see a bunch of files having ```.pyd``` and ```.dll``` file extensions and one file with ```.exe``` extension. So ```.pyd``` are just library files which contains python code which can be used by other applications and ```.dll``` are also dynamic libraries. On running the ```.exe``` it asks for a key and also if we try to run the ```.exe``` without the other files, it crashes, so we can simply conclude that all the other files are just for running the ```.exe``` and hence we can ignore other files and just focus on our binary and ```.exe``` file.

  

Note the name of the ```.exe``` which is ```seed.exe``` and the challenge is also talking about accessing some seed store. So what we have to do is to open the lock present in ```l0ck``` file and it will give some sort of key which we can use to open our ```seed.exe``` which should probably give us the flag.

  

## Cracking the l0ck

  

First we will analyze l0ck file. On running the file, we can see that the lock has 5 pins, opening each of them should do the work. It asks for a pin we want to open, lets enter 1, so it didnt work. Lets enter 2, it also didnt work. Lets enter 3, so now it further asks for 2 keys to open the pin. So we dont know what those keys are and on further entering 4 and 5 it still says the wrong the pin.

Lets use the ```strings``` command to print all the strings. Below are some strings which seems interesting.
```Remember sequence is the key!
A sequence in reverse direction is also a sequence!
*** Welcome to Lockitron 69 ***
**  Pin Usage: <key1> <key2> **
Which pin would you like to open?
Enter the keys: 
Hmmm, this pin won't budge!
Maybe try another one?
Hurray! you finally opened the lock!
Now put the numbers from the pins to a good use. Remember, sequence is the key!
```
Watch the repetition of word "sequence" in the strings and we also noted that we were only able to enter pin 3, so the pins must be present in some sort of sequence. Now lets open this binary in a decompiler, I am using ghidra here. Decompiling main function of the binary function gives us the following output
```C:
undefined8 main(void)
{
  int iVar1;
  int iVar2;
  char cVar3;
  basic_istream<char,std::char_traits<char>> *this;
  long in_FS_OFFSET;
  int local_28;
  int local_24;
  longlong local_20;
  longlong local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  std::operator<<((basic_ostream *)std::cout,"*** Welcome to Lockitron 69 ***\n");
  std::operator<<((basic_ostream *)std::cout,"**  Pin Usage: <key1> <key2> **\n");
  while( true ) {
    cVar3 = check();
    if (cVar3 == '\0') break;
    print_lock();
    std::operator<<((basic_ostream *)std::cout,"\nWhich pin would you like to open?\n");
    std::basic_istream<char,std::char_traits<char>>::operator>>
              ((basic_istream<char,std::char_traits<char>> *)std::cin,&local_28);
    cVar3 = lock_seq(local_28);
    if (cVar3 == '\0') {
      std::operator<<((basic_ostream *)std::cout,
                      "Hmmm, this pin won\'t budge!\nMaybe try another one?");
      for (local_24 = 0; local_24 < 5; local_24 = local_24 + 1) {
        *(undefined4 *)(pins + (long)local_24 * 4) = 1;
      }
    }
    else {
      std::operator<<((basic_ostream *)std::cout,"Enter the keys: ");
      this = (basic_istream<char,std::char_traits<char>> *)
             std::basic_istream<char,std::char_traits<char>>::operator>>
                       ((basic_istream<char,std::char_traits<char>> *)std::cin,&local_20);
      std::basic_istream<char,std::char_traits<char>>::operator>>(this,&local_18);
      iVar1 = (int)local_20;
      iVar2 = (int)local_18;
      if (local_28 == 1) {
        pin1(iVar1,iVar2);
      }
      else if (local_28 == 2) {
        pin2(iVar1,iVar2);
      }
      else if (local_28 == 3) {
        pin3(iVar1,iVar2);
      }
      else if (local_28 == 4) {
        pin4(iVar1,iVar2);
      }
      else if (local_28 == 5) {
        pin5(iVar1,iVar2);
      }
    }
  }
  cVar3 = check();
  if (cVar3 != '\x01') {
    print_lock();
    puts(
        "\nHurray! you finally opened the lock!\nNow put the numbers from the pins to a good use. Re member, sequence is the key!"
        );
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
We will analyze the while loop here. Firstly the code calls a check function whose disassembly is
```C:
undefined8 check(void)

{
  int local_c;
  
  local_c = 0;
  while( true ) {
    if (4 < local_c) {
      return 0;
    }
    if (*(int *)(pins + (long)local_c * 4) == 1) break;
    local_c = local_c + 1;
  }
  return 1;
}
```
It checks if the pins (which is an array of size 5 stored in data segment having values 1,1,1,1,1) have value equal to 1 or not and if it is 1  then increment local_c variable and if it values exceeds 4 then return false, else return true. So it is possibly checking if the all pins are unlocked or not since there only 5 pins which matches with array size.

Next line is taking input of the pin number which we want to open and storing in variable local_28 and then passing that input to function ```lock_seq```. Below is the disassembly of ```lock_seq```:
```C:
undefined lock_seq(int param_1)

{
  undefined local_15;
  int local_14;
  int local_10;
  int local_c;
  
  local_14 = -1;
  local_10 = 0;
  do {
    if (4 < local_10) {
LAB_001014ba:
      local_15 = 1;
      for (local_c = 0; local_c < local_14; local_c = local_c + 1) {
        if (*(int *)(pins + (long)(*(int *)(arr + (long)local_c * 4) + -1) * 4) == 1) {
          local_15 = 0;
        }
      }
      return local_15;
    }
    if (param_1 == *(int *)(arr + (long)local_10 * 4)) {
      local_14 = local_10;
      goto LAB_001014ba;
    }
    local_10 = local_10 + 1;
  } while( true );
}
```
There is an if condition in the function which compares our input with some element of an array ```arr```. Voila it is comparing our input with some stored array so it means our pin sequence must be stored somewhere in the data segment. On analyzing the data segment I found the sequence to be ```[3,5,1,4,2]``` and our first working pin number was also 3 so this sequence should be correct. 
Now we also have to unlock each pin for that we need 2 keys to open each pin. So going on further in our main function, we can ignore this if condition because this just checks if we have entered correct pin number or not but we already have the pin sequence now. 
In the else condition the program is taking input of the keys and then passing it to different functions based on our input (remember our entered key number was stored in local_28 variable). The disassembly for all the functions is mostly same so we have to analyze only one of them. Lets analyze function ```pin3``` since it is the first one to get called. 
```C:
void pin3(int param_1,int param_2)

{
  long lVar1;
  long lVar2;
  undefined8 uVar3;
  
  lVar1 = dhk((long)param_1,(long)param_2);
  lVar2 = dhk((long)arr._8_4_,(long)rev._8_4_);
  if (lVar1 == lVar2) {
    uVar3 = dhk((long)param_1,(long)param_2);
    printf("%lld",uVar3);
    puts("\nGood Job!");
    pins._8_4_ = 0;
  }
  else {
    puts("Remember sequence is the key!");
  }
  return;
}
```
Interestingly this function further calls a function ``dhk`` in which our entered keys  is passed and compared with output of the same function but this time passing some stored variables this time. If the comparison is successful it prints the value returned from the ``dhk``. So if the function is [one-one](https://en.wikipedia.org/wiki/Injective_function) we can conclude our keys are equal to that stored variables but if that is not the case then we have to further process it. Lets analyze ``dhk``
```C:
undefined8 dhk(longlong param_1,longlong param_2)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 uVar3;
  
  lVar1 = power(0x17,param_1,5000);
  lVar2 = power(0x17,param_2,5000);
  uVar3 = power(lVar2,param_1,5000);
  power(lVar1,param_2,5000);
  return uVar3;
}
```
Okay so looking at the decompilation this is clearly [Diffie Hellman Key Exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) which is also abbreviated as DHK  and yes it is one one function. So our keys are also stored in the data segment. 
Key 1 array: `` [3,5,1,4,2]``
Key 2 array: ``[2,4,1,5,3]``
On entering the keys in the binary we can see that keys don't work in the sequence given. "Remember sequence is the key"; so if we order the arrays index  according to our sequence of the pins the arrays comes out to be:
``[1,2,3,4,5]`` and ``[1,3,2,5,4]``. So our input is:
```
3
1 1
5
2 3
1
3 2
4
4 5
5
5 4  
```
We can see there is a number comes out whenever we open a pin and in the end it is also asking us to use these numbers with some sort of sequence, we have done enough analysis to conclude that our sequence is same as that of pins sequence because it is coming out everywhere. So putting the numbers in that sequence we get the number ``23889889201201``.
Enter this number in the ``seed.exe``, it gives us the flag.

