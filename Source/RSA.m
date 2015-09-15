//
//  RSA.m
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "RSA.h"
#import "RSAKey.h"
#import "RSAKey+Private.h"
#import "RSAKeyPair.h"
#import "RSAKeyPair+Private.h"
#import <Security/Security.h>


NSString *const RSAErrorDomain = @"RSAErrorDomain";

typedef NS_ENUM(NSUInteger, RSAKeyLoadOptions) {
    RSAKeyLoadOptionPassphrase = 1,
    RSAKeyLoadOptionItemType,
    RSAKeyLoadOptionFormat,
};

@implementation RSA

+ (RSAKeyPair *)generateKeyPairWithSize:(NSUInteger)numbits error:(out NSError **)error
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
            *error = [NSError errorWithDomain:RSAErrorDomain
                                         code:oserr
                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"SecKeyGeneratePair failed (oserr=%d)\n", oserr]}];
        }
        
        return nil;
    }
    
    RSAKeyPair *keyPair = [[RSAKeyPair alloc] initWithPublicKey:[[RSAKey alloc] initWithSecKey:publickey]
                                                     privateKey:[[RSAKey alloc] initWithSecKey:privatekey]];
    
    return keyPair;
}

+ (RSAKey *)importKey:(NSString *)keyPath passphrase:(NSString *)passphrase error:(out NSError **)outErr
{
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
            *outErr = [NSError errorWithDomain:RSAErrorDomain
                                          code:oserr
                                      userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"SecItemImport failed (oserr=%d)\n", oserr]}];
        }
        
        return nil;
    }
    
    SecKeyRef seckey = (SecKeyRef)CFArrayGetValueAtIndex(temparray, 0);
    
    return [[RSAKey alloc] initWithSecKey:seckey];
}

@end
