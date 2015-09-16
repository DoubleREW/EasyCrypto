//
//  RSA.m
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECRsa.h"
#import "ECRsaKey.h"
#import "ECRsaKey+Private.h"
#import "ECRsaKeyPair.h"
#import "ECRsaKeyPair+Private.h"
#import <Security/Security.h>


NSString *const ECRsaErrorDomain = @"RSAErrorDomain";

typedef NS_ENUM(NSUInteger, RSAKeyLoadOptions) {
    RSAKeyLoadOptionPassphrase = 1,
    RSAKeyLoadOptionItemType,
    RSAKeyLoadOptionFormat,
};

@implementation ECRsa

+ (ECRsaKeyPair *)generateKeyPairWithSize:(NSUInteger)numbits error:(out NSError **)error
{
    SecKeyRef publickey = nil;
    SecKeyRef privatekey = nil;
    
    CFMutableDictionaryRef parameters = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                  0,
                                                                  &kCFTypeDictionaryKeyCallBacks,
                                                                  &kCFTypeDictionaryValueCallBacks);
    
    CFDictionarySetValue(parameters, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionarySetValue(parameters, kSecAttrKeySizeInBits, (__bridge CFNumberRef)@(numbits));
    
    OSStatus oserr = SecKeyGeneratePair(parameters, &publickey, &privatekey);
    if (oserr != noErr) {
        if (error) {
            *error = [NSError errorWithDomain:ECRsaErrorDomain
                                         code:oserr
                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"SecKeyGeneratePair failed (oserr=%d)\n", oserr]}];
        }
        
        return nil;
    }
    
    ECRsaKeyPair *keyPair = [[ECRsaKeyPair alloc] initWithPublicKey:[[ECRsaKey alloc] initWithSecKey:publickey]
                                                     privateKey:[[ECRsaKey alloc] initWithSecKey:privatekey]];
    
    return keyPair;
}

+ (ECRsaKey *)importKey:(NSString *)keyPath passphrase:(NSString *)passphrase error:(out NSError **)outErr
{
    // TODO: iOS: http://stackoverflow.com/questions/10579985/how-can-i-get-seckeyref-from-der-pem-file
    CFErrorRef error = NULL;
    
    CFReadStreamRef cfrs = CFReadStreamCreateWithFile(kCFAllocatorDefault, (__bridge CFURLRef)[NSURL fileURLWithPath:keyPath]);
    SecTransformRef readTransform = SecTransformCreateReadTransformWithReadStream(cfrs);
    CFDataRef keydata = SecTransformExecute(readTransform, &error);
    
    
    // - Import key
    SecItemImportExportKeyParameters params;
    
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0; // See SecKeyImportExportFlags for details.
    params.passphrase = (passphrase ? (__bridge CFStringRef)passphrase : NULL);
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    params.accessRef = NULL;
    
    params.keyUsage = NULL;
    params.keyAttributes = NULL;
    
    SecExternalItemType itemType = kSecItemTypeCertificate; // kSecItemTypeCertificate
    SecExternalFormat externalFormat = kSecFormatPEMSequence; // kSecFormatPKCS7
    int flags = 0;
    CFArrayRef temparray = nil;
    
    OSStatus oserr = SecItemImport(keydata,
                                   NULL, // filename or extension
                                   &externalFormat, // See SecExternalFormat for details
                                   &itemType, // item type
                                   flags, // See SecItemImportExportFlags for details
                                   &params,
                                   NULL, // Don't import into a keychain
                                   &temparray);
    
    if (oserr) {
        if (outErr) {
            *outErr = [NSError errorWithDomain:ECRsaErrorDomain
                                          code:oserr
                                      userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"SecItemImport failed (oserr=%d)\n", oserr]}];
        }
        
        return nil;
    }
    
    SecKeyRef seckey = (SecKeyRef)CFArrayGetValueAtIndex(temparray, 0);
    
    return [[ECRsaKey alloc] initWithSecKey:seckey];
}

@end
