#include <napi.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include "chacha20.h"
#include <array>
using namespace std;
namespace chacha {
    string encryptString(string toEncrypt, string key, string iv);
    string decryptString(string enc, string key,  string iv);

    Napi::String EncryptWrapped(const Napi::CallbackInfo& info);
    Napi::String DecryptWrapped(const Napi::CallbackInfo& info);
    Napi::Object Init(Napi::Env env, Napi::Object exports);
    
}
