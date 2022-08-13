#include "pch.h"
#include "Wallet.h"
#include "Utility.h"
#include <stdio.h>

void print_wallet(const wallet_t* wallet) {
    printf("\n-----------------------------------------\n\n");
    printf("Simple password wallet based on Intel SGX.\n\n");
    printf("Number of items: %lu\n\n", wallet->size);
    for (int i = 0; i < wallet->size; ++i) {
        printf("#%d -- %s\n", i, wallet->items[i].title);
        printf("[username:] %s\n", wallet->items[i].username);
        printf("[password:] %s\n", wallet->items[i].password);
        printf("\n");
    }
    printf("\n------------------------------------------\n\n");
}