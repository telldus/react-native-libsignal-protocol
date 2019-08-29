#import "RNOMEMOCipher.h"

@implementation RNOMEMOCipher

// To export a module named RNOMEMOCipher
RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(generateRegistrationId:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSNumber *num = @1;
    resolve(num);
}

RCT_EXPORT_METHOD(generateIdentityKeyPair:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *dict = @{ @"key" : @"value", @"key2" : @"value2"};
    resolve(dict);
}

RCT_EXPORT_METHOD(generatePreKeys:(NSNumber *)startId count:(NSNumber *)count resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *dict = @{ @"key" : @"value", @"key2" : @"value2"};
    NSArray *arr = @[dict];
    resolve(arr);
}

RCT_EXPORT_METHOD(generateSignedPreKey:(NSDictionary *)identityKeyPair signedKeyId:(NSNumber *)signedKeyId resolver:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *dict = @{ @"key" : @"value", @"key2" : @"value2"};
    resolve(dict);
}

RCT_EXPORT_METHOD(buildSession:(NSString *)recipientId deviceListAndBundle:(NSArray *)deviceListAndBundle resolver:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSNumber *output=[NSNumber numberWithBool:YES];
    resolve(output);
}

RCT_EXPORT_METHOD(encryptSignalProtocol:(NSString *)message 
                recipientId:(NSString *)recipientId
                deviceId:(NSNumber *)deviceId
                resolver:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSString *str = @"string";
    resolve(str);
}

RCT_EXPORT_METHOD(decryptSignalProtocol:(NSString *)message 
                recipientId:(NSString *)recipientId
                deviceId:(NSNumber *)deviceId
                resolver:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSString *str = @"string";
    resolve(str);
}

RCT_EXPORT_METHOD(loadPreKeys:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSArray *arr = @[@"pre"];
    resolve(arr);
}


// OMEMO

RCT_EXPORT_METHOD(encryptOMEMO:
                (NSString *)ownId
                ownDeviceId:(NSString *)ownDeviceId
                recipientId:(NSString *)recipientId 
                deviceList:(NSArray *)deviceList
                message:(NSString *)message 
                resolver:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSString *str = @"string";
    resolve(str);
}

RCT_EXPORT_METHOD(decryptOMEMO:(NSString *)recipientId 
                ownDeviceId:(NSString *)ownDeviceId
                iv:(NSString *)iv
                keysList:(NSArray *)keysList
                cipherText:(NSString *)cipherText
                resolver:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSString *str = @"string";
    resolve(str);
}


// Curve25519

RCT_EXPORT_METHOD(generateCurve25519KeyPair:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *dict = @{ @"key" : @"value", @"key2" : @"value2"};
    resolve(dict);
}

RCT_EXPORT_METHOD(storeCurve25519KeyPair:(NSString *)publicKey 
                privateKey:(NSString *)privateKey
                resolver:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSNumber *output=[NSNumber numberWithBool:YES];
    resolve(output);
}

RCT_EXPORT_METHOD(loadCurve25519KeyPair:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *dict = @{ @"key" : @"value", @"key2" : @"value2"};
    resolve(dict);
}


// Ed25519OctetKey

RCT_EXPORT_METHOD(generateEd25519OctetKeyPair:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *dict = @{ @"key" : @"value", @"key2" : @"value2"};
    resolve(dict);
}

RCT_EXPORT_METHOD(loadEd25519OctetKeyPair:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *dict = @{ @"key" : @"value", @"key2" : @"value2"};
    resolve(dict);
}

RCT_EXPORT_METHOD(createJWTFromEd25519OctetKeyPair:
                (NSString *)subject 
                issuer:(NSString *)issuer
                expirationTimeStamp:(NSString *)expirationTimeStamp
                claimName:(NSString *)claimName
                claimValue:(NSString *)claimValue
                keyPairJSONString:(NSString *)keyPairJSONString
                resolver:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSString *str = @"string";
    resolve(str);
}

RCT_EXPORT_METHOD(verifyJWT:
                (NSString *)jwt 
                publicJWK:(NSString *)publicJWK
                claimName:(NSString *)claimName
                claimValue:(NSString *)claimValue
                resolver:(RCTPromiseResolveBlock)resolve
                rejecter:(RCTPromiseRejectBlock)reject)
{
    NSDictionary *dict = @{ @"key" : @"value", @"key2" : @"value2"};
    resolve(dict);
}

@end
