#pragma once
#include "pch.h"
#include "WrapperCalling.h"

#include <stdio.h>
#include <tchar.h>

#define ENCLAVE_FILE _T("C:\\Personal\\ProjectFinal\\Enclave\\Debug\\Enclave.signed.dll")
#define MAX_BUF_LEN 100
#include "sgx_urts.h"
#include "Enclave_u.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include "Utility.h"

using namespace std;

CallingEnclave::CallingEnclave(int x) {
	this->x = x;
}

void CallingEnclave::Call()
{
    sgx_enclave_id_t   eid;
    sgx_status_t       ret = SGX_SUCCESS;
    sgx_launch_token_t token = { 0 };
    int updated = 0;
    char buffer[MAX_BUF_LEN] = "Hello World!";
    char secret[MAX_BUF_LEN] = "My secret string";
    char retSecret[MAX_BUF_LEN] = "";
    int secretIntValue = 0;
    int* secretIntPointer = &secretIntValue;

    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);

    if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to create enclave.\n", ret);
    }
    else
    {
        printf("\nApp: Enclave Created successfully.\n", &eid);
    }

    printf("\nApp: Buffertests:\n");

    // Change the buffer in the enclave
    printf("App: Buffer before change: %s\n", buffer);
    enclaveChangeBuffer(eid, buffer, MAX_BUF_LEN);
    printf("App: Buffer after change: %s\n", buffer);

    ret = sgx_destroy_enclave(eid);
    if (ret != SGX_SUCCESS) {
        printf("Fail to destroy enclave.");
        return;
    }
}


int CallingEnclave::CallWallet(int argc, char** deviceId, char** username, char** password, char** olPassword)
{
    sgx_enclave_id_t   eid;
    int updated, ret;
    sgx_status_t ecall_status, enclave_status;

    sgx_launch_token_t token = { 0 };
  /*  char buffer[MAX_BUF_LEN] = "Hello World!";
    char secret[MAX_BUF_LEN] = "My secret string";
    char retSecret[MAX_BUF_LEN] = "";*/
    int secretIntValue = 0;
    int* secretIntPointer = &secretIntValue;

    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    char* n_value = NULL, * p_value = NULL, * c_value = NULL, * x_value = NULL, * y_value = NULL, * z_value = NULL, * r_value = NULL;
    if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to create enclave.\n", ret);
        return 0;
    }
    else
    {
        printf("\nApp: Enclave Created successfully.\n", &eid);
    }

    //Create Wallet
    if (argc == 1)
    {

        ecall_status = create_wallet(eid, &ret, "dinesh");
        if (ecall_status != SGX_SUCCESS) {
            printf("Fail to create new wallet.", ret);
            return 0;
        }
        else {
            printf("Wallet successfully created.", ret);
        }
    }
    else if (argc == 2)
    {

        //Display Wallet
        wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
        ecall_status = show_wallet(eid, &ret, n_value, wallet, sizeof(wallet_t));
        if (ecall_status != SGX_SUCCESS) {
            printf("Fail to retrieve wallet.");
            return 0;
        }
        else {
            printf("Wallet successfully retrieved.");
            print_wallet(wallet);
        }
        free(wallet);
        return 1;
    }
    else if (argc == 3)
    {

        //Change Master Password.
        ecall_status = change_master_password(eid, &ret, p_value, c_value);
        if (ecall_status != SGX_SUCCESS) {
            printf("Fail change master-password.");
            return 0;
        }
        else {
            printf("Master-password successfully changed.");
            return 1;
        }
    }
    else if (argc == 4)
    {


        //Add item
        item_t* new_item = (item_t*)malloc(sizeof(item_t));
        strcpy_s(new_item->title, x_value);
        strcpy_s(new_item->username, y_value);
        strcpy_s(new_item->password, z_value);
        ecall_status = add_item(eid, &ret, p_value, new_item, sizeof(item_t));
        if (ecall_status != SGX_SUCCESS) {
            printf("Fail to add new item to wallet.");
            return 0;
        }
        else {
            printf("Item successfully added to the wallet.");
        }
        free(new_item);
        return 1;
    }
    else if (argc == 5)
    {


        // Remove Item
        char* p_end;
        int index = (int)strtol(r_value, &p_end, 10);
        if (r_value == p_end) {
            printf("Option -r requires an integer argument.");
        }
        else {
            ecall_status = remove_item(eid, &ret, p_value, index);
            if (ecall_status != SGX_SUCCESS) {
                printf("Fail to remove item.");
                return 0;
            }
            else {
                printf("Item successfully removed from the wallet.");
            }
            return 1;
        }
    }
    else
    {
        printf("Invalid command.");
    }

    enclave_status = sgx_destroy_enclave(eid);
    if (enclave_status != SGX_SUCCESS) {
        printf("Fail to destroy enclave.");
        return 0;;
    }
    //printf("Enclave successfully destroyed.");

    printf("\nEnclave Program exit successfully");
    return 1;
}


int save_wallet(const uint8_t* sealed_data, const size_t sealed_size) {
    ofstream file("wallet.seal", ios::out | ios::binary);
    if (file.fail()) { return 1; }
    file.write((const char*)sealed_data, sealed_size);
    file.close();
    return 0;
}

int ocall_load_wallet(uint8_t* sealed_data, const size_t sealed_size) {
    ifstream file("wallet.seal", ios::in | ios::binary);
    if (file.fail()) { return 1; }
    file.read((char*)sealed_data, sealed_size);
    file.close();
    return 0;
}

int ocall_is_wallet(void) {
    ifstream file("wallet.seal", ios::in | ios::binary);
    if (file.fail()) { return 0; } // failure means no wallet found
    file.close();
    return 1;
}


