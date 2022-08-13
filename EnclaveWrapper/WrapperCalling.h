#pragma once
class CallingEnclave {
	int x;
public:
	CallingEnclave(int x);
	void Call();
	int CallWallet(int argc, char** deviceId, char** username, char** password, char** oldPassword);
	//int Sealing(sgx_enclave_id_t eid);
};


extern "C" __declspec(dllexport) void* CreateObj(int x) {
	return (void*) new CallingEnclave(x);
}

extern "C" __declspec(dllexport) void Call(CallingEnclave * a) {
	a->Call();
}


extern "C" __declspec(dllexport) int CallWallet(CallingEnclave * a, int argc, char** deviceId, char** username, char** password, char** oldPassword) {
	return	a->CallWallet(argc, deviceId, username, password, oldPassword);
}