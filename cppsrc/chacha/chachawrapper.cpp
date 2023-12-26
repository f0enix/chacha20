#include "chachawrapper.h"

std::string chacha::encryptString(string toEncrypt, string key, string iv){
    char *input_string = (char*) (toEncrypt.c_str());
    char* cEncrypted = encryptChacha(input_string, (char*) (key.c_str()), (char*) (iv.c_str()));
    return cEncrypted;
}

Napi::String chacha::EncryptWrapped(const Napi::CallbackInfo& info) {
    Napi::String str = info[0].As<Napi::String>();
    Napi::String key = info[1].As<Napi::String>();
    Napi::String iv = info[2].As<Napi::String>();

    Napi::Env env = info.Env();
    Napi::String returnValue = Napi::String::New(env, chacha::encryptString(str, key, iv));
    return returnValue;
}


std::string chacha::decryptString(string enc, string key, string iv){
    char *encryptedStr = (char*) (enc.c_str());
    char* decryptedStr = decryptChacha(encryptedStr, (char*) (key.c_str()), (char*) (iv.c_str()));
    return decryptedStr;
}

Napi::String chacha::DecryptWrapped(const Napi::CallbackInfo& info) {
    Napi::String str = info[0].As<Napi::String>();
    Napi::String key = info[1].As<Napi::String>();
    Napi::String iv = info[2].As<Napi::String>();
    Napi::Env env = info.Env();
    Napi::String returnValue = Napi::String::New(env, chacha::decryptString(str, key, iv));
    return returnValue;
}

Napi::Object chacha::Init(Napi::Env env, Napi::Object exports) {
    exports.Set("encrypt", Napi::Function::New(env, chacha::EncryptWrapped));
    exports.Set("decrypt", Napi::Function::New(env, chacha::DecryptWrapped));
    
    return exports;
}
