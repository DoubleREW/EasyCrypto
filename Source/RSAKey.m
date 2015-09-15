//
//  RSAKey.m
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "RSAKey.h"
#import "RSASignature.h"
#import "RSASignature+Private.h"

NSString *const RSAKeyErrorDomain = @"RSAKeyErrorDomain";
NSInteger RSAKeyVerificationFailedErrorCode = 500;

static CFBooleanRef RSADigestTypeCFConversion(RSADigestType digestType, CFStringRef *digestTypeString, CFNumberRef *digestLen)
{
    switch (digestType) {
        case RSADigestTypeMD5:
            *digestTypeString = kSecDigestMD5;
            *digestLen = (__bridge CFNumberRef)@(128);
            break;
        case RSADigestTypeSHA1:
            *digestTypeString = kSecDigestSHA1;
            *digestLen = (__bridge CFNumberRef)@(160);
            break;
        case RSADigestTypeSHA224:
            *digestTypeString = kSecDigestSHA2;
            *digestLen = (__bridge CFNumberRef)@(224);
            break;
        case RSADigestTypeSHA256:
            *digestTypeString = kSecDigestSHA2;
            *digestLen = (__bridge CFNumberRef)@(256);
            break;
        case RSADigestTypeSHA384:
            *digestTypeString = kSecDigestSHA2;
            *digestLen = (__bridge CFNumberRef)@(384);
            break;
        case RSADigestTypeSHA512:
            *digestTypeString = kSecDigestSHA2;
            *digestLen = (__bridge CFNumberRef)@(512);
            break;
            
        case RSADigestTypeNone:
        default:
            return kCFBooleanFalse;
    }
    
    return kCFBooleanTrue;
}


@implementation RSAKey
{
    SecKeyRef _key;
}

- (instancetype)initWithSecKey:(SecKeyRef)key
{
    self = [super init];
    if (self) {
        _key = key;
    }
    
    return self;
}

- (RSASignature *)sign:(NSData *)data digestType:(RSADigestType)digestTypeRaw error:(out NSError **)outErr
{
    CFErrorRef error = NULL;
    
    SecTransformRef signer = SecSignTransformCreate(_key, &error); // PKCS#1 v1.5 (non impostabile su osx)
    if (error) {
        if (outErr) *outErr = (__bridge NSError *)error;
        return nil;
    }
    
    SecTransformSetAttribute(signer,
                             kSecTransformInputAttributeName,
                             (__bridge CFDataRef)data,
                             &error);
    if (error) {
        if (outErr) *outErr = (__bridge NSError *)error;
        return nil;
    }
    
    // -- Hash
    CFStringRef digestType = NULL;
    CFNumberRef digestLen = NULL;
    if (RSADigestTypeCFConversion(digestTypeRaw, &digestType, &digestLen) == kCFBooleanTrue) {
        SecTransformSetAttribute(signer,
                                 kSecDigestTypeAttribute,
                                 digestType,
                                 &error);
        if (error) {
            if (outErr) *outErr = (__bridge NSError *)error;
            return nil;
        }
        
        SecTransformSetAttribute(signer,
                                 kSecDigestLengthAttribute,
                                 digestLen,
                                 &error);
        if (error) {
            if (outErr) *outErr = (__bridge NSError *)error;
            return nil;
        }
    }
    
    // -- Sign
    CFDataRef signature = SecTransformExecute(signer, &error);
    if (error) {
        if (outErr) *outErr = (__bridge NSError *)error;
        return nil;
    }
    
    if (!signature) {
        if (outErr) {
            *outErr = [NSError errorWithDomain:RSAKeyErrorDomain
                                         code:-1
                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Signature is NULL!\n"]}];
        }
        return nil;
    }
    
    return [[RSASignature alloc] initWithRawData:(__bridge NSData *)signature];
}

- (BOOL)verify:(NSData *)data signature:(RSASignature *)signature digestType:(RSADigestType)digestTypeRaw error:(out NSError **)outErr
{
    CFErrorRef error = NULL;
    
    SecTransformRef verifier = SecVerifyTransformCreate(_key, (__bridge CFDataRef)signature.rawData, &error); // PKCS#1 v1.5 (non impostabile su osx)
    if (error) {
        if (outErr) *outErr = (__bridge NSError *)error;
        return NO;
    }
    
    SecTransformSetAttribute(verifier,
                             kSecTransformInputAttributeName,
                             (__bridge CFDataRef)data,
                             &error);
    if (error) {
        if (outErr) *outErr = (__bridge NSError *)error;
        return NO;
    }
    
    // -- Hash
    CFStringRef digestType = NULL;
    CFNumberRef digestLen = NULL;
    if (RSADigestTypeCFConversion(digestTypeRaw, &digestType, &digestLen) == kCFBooleanTrue) {
        SecTransformSetAttribute(verifier,
                                 kSecDigestTypeAttribute,
                                 digestType,
                                 &error);
        if (error) {
            if (outErr) *outErr = (__bridge NSError *)error;
            return NO;
        }
        
        SecTransformSetAttribute(verifier,
                                 kSecDigestLengthAttribute,
                                 digestLen,
                                 &error);
        if (error) {
            if (outErr) *outErr = (__bridge NSError *)error;
            return NO;
        }
    }
    
    // -- Verify
    CFBooleanRef verified = SecTransformExecute(verifier, &error);
    if (error) {
        if (outErr) *outErr = (__bridge NSError *)error;
        return NO;
    }
    
    if (verified == kCFBooleanFalse) {
        if (outErr) {
            *outErr = [NSError errorWithDomain:RSAKeyErrorDomain
                                          code:RSAKeyVerificationFailedErrorCode
                                      userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Data can't be verified!\n"]}];
        }
        return NO;
    }else {
        if (outErr) {
            *outErr = nil;
        }
        return YES;
    }
}

- (nullable NSData *)exportKey:(RSAExportFormat)format error:(out NSError * _Nullable * _Nullable)outErr
{
    SecItemImportExportKeyParameters params;
    
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0; // See SecKeyImportExportFlags for details.
    params.passphrase = NULL;
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    params.accessRef = NULL;
    
    CFMutableArrayRef keyUsage = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    
    /* This example sets a lot of usage values.
     Choose usage values that are appropriate
     to your specific task. Possible values begin
     with kSecAttrCan, and are defined in
     SecItem.h */
    CFArrayAppendValue(keyUsage, kSecAttrCanEncrypt);
    CFArrayAppendValue(keyUsage, kSecAttrCanDecrypt);
    CFArrayAppendValue(keyUsage, kSecAttrCanDerive);
    CFArrayAppendValue(keyUsage, kSecAttrCanSign);
    CFArrayAppendValue(keyUsage, kSecAttrCanVerify);
    CFArrayAppendValue(keyUsage, kSecAttrCanWrap);
    CFArrayAppendValue(keyUsage, kSecAttrCanUnwrap);
    
    CFMutableArrayRef keyAttributes = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    
    params.keyUsage = keyUsage;
    params.keyAttributes = keyAttributes;
    
    SecExternalFormat externalFormat = kSecFormatPEMSequence;
    int flags = 0;
    CFDataRef keydata = nil;
    
    OSStatus oserr = SecItemExport(_key,
                                     externalFormat, // See SecExternalFormat for details
                                     flags, // See SecItemImportExportFlags for details
                                     &params,
                                     (CFDataRef *)&keydata);
    if (oserr) {
        if (outErr) {
            *outErr = [NSError errorWithDomain:RSAKeyErrorDomain
                                          code:oserr
                                      userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"SecItemExport failed (oserr=%d)\n", oserr]}];
        }
        
        return nil;
    }
    
    return (__bridge NSData *)keydata;
}

@end
