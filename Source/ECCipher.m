//
//  ECCipher.m
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECCipher.h"
#import "ECCipher+Private.h"
#import "ECCipherData.h"
#import "ECCipherData+Private.h"


NSString *const ECCipherError = @"ECCipherError";
NSInteger ECCipherEncryptionError = 701;
NSInteger ECCipherDecryptionError = 702;

ECCipherMode ECCipherModeDefault = ECCipherModeCBC;
ECCipherPadding ECCipherPaddingDefault = ECCipherPaddingNone;
NSInteger ECCipherBlockSizeNotProvided = -1;


CCAlgorithm CCAlgorithmFromCipherAlg(ECCipherAlgorithm alg)
{
    switch (alg) {
        case ECCipherAlgorithmAES128:
            return kCCAlgorithmAES;
        case ECCipherAlgorithmDES:
            return kCCAlgorithmDES;
        case ECCipherAlgorithm3DES:
            return kCCAlgorithm3DES;
        case ECCipherAlgorithmCAST:
            return kCCAlgorithmCAST;
        case ECCipherAlgorithmRC2:
            return kCCAlgorithmRC2;
        case ECCipherAlgorithmBlowfish:
            return kCCAlgorithmBlowfish;
            
        default:
            fprintf(stderr, "Invalid cipher algorithm (%ld)", alg);
            assert(false);
    }
}

CCMode CCModeFromCipherMode(ECCipherMode mode)
{
    switch (mode) {
        case ECCipherModeECB:
            return kCCModeECB;
        case ECCipherModeCBC:
            return kCCModeCBC;
        case ECCipherModeCFB:
            return kCCModeCFB;
        case ECCipherModeCTR:
            return kCCModeCTR;
        case ECCipherModeOFB:
            return kCCModeOFB;
        case ECCipherModeXTS:
            return kCCModeXTS;
        case ECCipherModeRC4:
            return kCCModeRC4;
        case ECCipherModeCFB8:
            return kCCModeCFB8;
            
        default:
            fprintf(stderr, "Invalid cipher mode (%ld)", mode);
            assert(false);
    }
}

CCPadding CCPaddingFromCipherPadding(ECCipherPadding padding)
{
    switch (padding) {
        case ECCipherPaddingNone:
            return ccNoPadding;
        case ECCipherPaddingPKCS7:
            return ccPKCS7Padding;
            
        default:
            fprintf(stderr, "Invalid cipher padding (%ld)", padding);
            assert(false);
    }
}

static NSString * GetCCCryptorStatusString(CCCryptorStatus status)
{
    switch (status) {
        case kCCSuccess:
            return @"Operation completed normally.";
        case kCCParamError:
            return @"Illegal parameter value.";
        case kCCBufferTooSmall:
            return @"Insufficent buffer provided for specified operation.";
        case kCCMemoryFailure:
            return @"Memory allocation failure.";
        case kCCAlignmentError:
            return @"Input size was not aligned properly.";
        case kCCDecodeError:
            return @"Input data did not decode or decrypt properly.";
        case kCCUnimplemented:
            return @"Function not implemented for the current algorithm.";
        case kCCOverflow:
            return @"Overflow";
        case kCCRNGFailure:
            return @"Failure";
            
        default:
            return @"";
    }
}

@interface NSError (ECCipher)
+ (NSError *)errorWithCCStatus:(CCCryptorStatus)status;
@end
@implementation NSError (ECCipher)
+ (NSError *)errorWithCCStatus:(CCCryptorStatus)status
{
    return [NSError errorWithDomain:ECCipherError
                               code:status
                           userInfo:@{NSLocalizedDescriptionKey: GetCCCryptorStatusString(status)}];
}
@end


@interface ECCipher ()
{
    @public
    CCCryptorRef _encryptor;
    CCCryptorRef _decryptor;
}

// @property (nonatomic, assign) ECCipherAlgorithm algorithm;
@property (nonatomic, assign) ECCipherMode mode;
@property (nonatomic, assign) ECCipherPadding padding;
// @property (nonatomic, assign) NSInteger blockSize;
@property (nonatomic, assign) NSInteger keySize;
@property (nonatomic, strong) NSData *key;
@property (nonatomic, strong) NSData *iv;


- (CCCryptorStatus)createEncryptor;
- (CCCryptorStatus)createDecryptor;

+ (BOOL)validateKeySize:(NSInteger)keySize;

@end

@implementation ECCipher

- (instancetype)init
{
    self = [super init];
    if (self) {
        if([self class] == [ECCipher class]) {
            [NSException raise:NSInternalInconsistencyException
                        format:@"Subclasses must overload this method"];
        }
    }
    
    return self;
}

- (instancetype)initWithDataKey:(NSData *)key mode:(ECCipherMode)mode padding:(ECCipherPadding)padding iv:(NSData *)iv;
{
    self = [self init];
    if (self) {
        if (iv != nil)
            NSAssert2([self blockSize] == [iv length], @"The inizialization vector's length must be equal to the algorithm's block size (%ld != %ld).", [iv length], [self blockSize]);
        
        NSAssert1([[self class] validateDataKey:key], @"The size of the key (%ld) is not valid for this algorithm.", [key length]);
        
        _key = key;
        _keySize = [key length];
        _mode = mode;
        _padding = padding;
        _iv = iv;
    }
    
    return self;
}

- (instancetype)initWithDataKey:(NSData *)key mode:(ECCipherMode)mode
{
    return [self initWithDataKey:key mode:mode padding:ECCipherPaddingDefault iv:nil];
}

- (instancetype)initWithDataKey:(NSData *)key iv:(NSData *)iv
{
    return [self initWithDataKey:key mode:ECCipherModeDefault padding:ECCipherPaddingDefault iv:iv];
}

- (instancetype)initWithDataKey:(NSData *)key
{
    return [self initWithDataKey:key iv:nil];
}

- (instancetype)initWithStringKey:(NSString *)key mode:(ECCipherMode)mode padding:(ECCipherPadding)padding iv:(NSData *)iv;
{
    return [self initWithDataKey:[key dataUsingEncoding:NSUTF8StringEncoding]
                          mode:mode
                         padding:padding
                              iv:iv];
}

- (instancetype)initWithStringKey:(NSString *)key iv:(NSData *)iv;
{
    return [self initWithStringKey:key mode:ECCipherModeDefault padding:ECCipherPaddingDefault iv:iv];
}

- (instancetype)initWithStringKey:(NSString *)key mode:(ECCipherMode)mode;
{
    return [self initWithStringKey:key mode:mode padding:ECCipherPaddingDefault iv:nil];
}

- (instancetype)initWithStringKey:(NSString *)key;
{
    return [self initWithStringKey:key iv:nil];
}

- (void)dealloc
{
    CCCryptorRelease(_encryptor);
    CCCryptorRelease(_decryptor);
}

- (ECCipherAlgorithm)algorithm
{
    return [[self class] algorithm];
}

- (NSInteger)blockSize
{
    return [[self class] blockSize];
}

- (CCCryptorStatus)createCryptorForOperation:(CCOperation)op cryptor:(CCCryptorRef *)cryptor
{
    char keyPtr[self.keySize+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [self.key getBytes:keyPtr length:sizeof(keyPtr)];
    
    return CCCryptorCreateWithMode(
                            op,
                            CCModeFromCipherMode(self.mode),
                            CCAlgorithmFromCipherAlg(self.algorithm),
                            CCPaddingFromCipherPadding(self.padding),
                            (self.iv ? [self.iv bytes] : NULL),
                            keyPtr, self.keySize,
                            NULL, 0, 0, 0,
                            cryptor);
}

- (CCCryptorStatus)createEncryptor
{
    return [self createCryptorForOperation:kCCEncrypt cryptor:&_encryptor];
}

- (CCCryptorStatus)createDecryptor
{
    return [self createCryptorForOperation:kCCDecrypt cryptor:&_decryptor];
}

- (CCCryptorStatus)resetCryptor:(CCCryptorRef)cryptor
{
    return CCCryptorReset(cryptor, NULL);
}

- (NSData *)executeCryptor:(CCCryptorRef)cryptor withData:(NSData *)data error:(NSError **)error;
{
    CCCryptorStatus ccStatus = kCCSuccess;
    uint8_t * bufferPtr = NULL; // Pointer to output buffer.
    size_t bufferPtrSize = 0; // Total size of the buffer.
    size_t remainingBytes = 0; // Remaining bytes to be performed on.
    size_t movedBytes = 0; // Number of bytes moved to buffer.
    size_t plainTextBufferSize = [data length]; // Length of plainText buffer.
    size_t totalBytesWritten = 0; // Placeholder for total written.
    uint8_t * ptr; // A friendly helper pointer.
    
    
    // Calculate byte block alignment for all calls through to and including final.
    bufferPtrSize = CCCryptorGetOutputLength(cryptor, plainTextBufferSize, true);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t)); // Allocate buffer.
    memset((void *)bufferPtr, 0x0, bufferPtrSize); // Zero out buffer.
    ptr = bufferPtr; // Initialize some necessary book keeping.
    
    remainingBytes = bufferPtrSize; // Set up initial size.
    
    ccStatus = CCCryptorUpdate(cryptor, [data bytes], plainTextBufferSize, ptr, remainingBytes, &movedBytes);
    
    // Check for errors
    if (ccStatus != kCCSuccess) {
        if (error) {
            *error = [NSError errorWithCCStatus:ccStatus];
            return nil;
        }
    }
    
    // Handle book keeping.
    ptr += movedBytes;
    remainingBytes -= movedBytes;
    totalBytesWritten += movedBytes;
    
    // Finalize everything to the output buffer.
    ccStatus = CCCryptorFinal(cryptor, ptr, remainingBytes, &movedBytes);
    
    totalBytesWritten += movedBytes;
    
    if (ccStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:bufferPtr length:totalBytesWritten];
    }
    
    if (bufferPtr)
        free(bufferPtr); //free the buffer;
    
    if (error)
        *error = [NSError errorWithCCStatus:ccStatus];
    
    return nil;
}

- (ECCipherEncryptedData *)encryptData:(NSData *)data error:(NSError **)error;
{
    // Clean cryptor
    CCCryptorStatus ccStatus;
    
    if (_encryptor == NULL)
        ccStatus = [self createEncryptor];
    else
        ccStatus = [self resetCryptor:_encryptor];
    
    if (ccStatus != kCCSuccess) {
        if (error) {
            *error = [NSError errorWithCCStatus:ccStatus];
            return nil;
        }
    }

    
    NSData *encryptedData = [self executeCryptor:_encryptor withData:data error:error];
    return [[ECCipherEncryptedData alloc] initWithData:encryptedData];
}

- (ECCipherEncryptedData *)encryptString:(NSString *)str error:(NSError **)error
{
    return [self encryptData:[str dataUsingEncoding:NSUTF8StringEncoding] error:error];
}

- (ECCipherEncryptedData *)encrypt:(NSString *)str error:(NSError **)error
{
    return [self encryptString:str error:error];
}

- (ECCipherPlainData *)decryptData:(NSData *)data error:(NSError **)error
{
    // Clean cryptor
    CCCryptorStatus ccStatus;
    
    if (_decryptor == NULL)
        ccStatus = [self createDecryptor];
    else
        ccStatus = [self resetCryptor:_decryptor];
    
    if (ccStatus != kCCSuccess) {
        if (error) {
            *error = [NSError errorWithCCStatus:ccStatus];
            return nil;
        }
    }
    
    
    NSData *decryptedData = [self executeCryptor:_decryptor withData:data error:error];
    return [[ECCipherPlainData alloc] initWithData:decryptedData];
}

- (ECCipherPlainData *)decrypt:(ECCipherEncryptedData *)encryptedData error:(NSError **)error
{
    return [self decryptData:encryptedData.rawData error:error];
}

// MARK: Class methods
+ (ECCipherAlgorithm)algorithm
{
    return ECCipherAlgorithmAES;
}

+ (NSInteger)blockSize
{
    return ECCipherBlockSizeNotProvided;
}

+ (BOOL)validateKeySize:(NSInteger)keySize
{
    return NO;
}

+ (BOOL)validateDataKey:(NSData *)key
{
    return [self validateKeySize:[key length]];
}

+ (BOOL)validateStringKey:(NSString *)key
{
    return [self validateDataKey:[key dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (BOOL)validateKey:(NSString *)key
{
    return [self validateStringKey:key];
}

@end

// MARK: Implementations
@implementation ECCipherAES

+ (ECCipherAlgorithm)algorithm
{
    return ECCipherAlgorithmAES;
}

+ (NSInteger)blockSize
{
    return kCCBlockSizeAES128;
}

+ (BOOL)validateKeySize:(NSInteger)keySize
{
    return keySize == kCCKeySizeAES128 || keySize == kCCKeySizeAES192 || keySize == kCCKeySizeAES256;
}

+ (nonnull NSArray<NSNumber *> *)keySizes
{
    return @[@(kCCKeySizeAES128), @(kCCKeySizeAES192), @(kCCKeySizeAES256)];
}

@end

@implementation ECCipherDES

+ (ECCipherAlgorithm)algorithm
{
    return ECCipherAlgorithmDES;
}

+ (NSInteger)blockSize
{
    return kCCBlockSizeDES;
}

+ (BOOL)validateKeySize:(NSInteger)keySize
{
    return keySize == kCCKeySizeDES;
}

+ (nonnull NSArray<NSNumber *> *)keySizes
{
    return @[@(kCCKeySizeDES)];
}

@end

@implementation ECCipher3DES


+ (ECCipherAlgorithm)algorithm
{
    return ECCipherAlgorithm3DES;
}

+ (NSInteger)blockSize
{
    return kCCBlockSize3DES;
}

+ (BOOL)validateKeySize:(NSInteger)keySize
{
    return keySize == kCCKeySize3DES;
}

+ (nonnull NSArray<NSNumber *> *)keySizes
{
    return @[@(kCCKeySize3DES)];
}

@end

@implementation ECCipherCAST


+ (ECCipherAlgorithm)algorithm
{
    return ECCipherAlgorithmCAST;
}

+ (NSInteger)blockSize
{
    return kCCBlockSizeCAST;
}

+ (BOOL)validateKeySize:(NSInteger)keySize
{
    return keySize >= kCCKeySizeMinCAST && keySize <= kCCKeySizeMaxCAST;
}

+ (NSInteger)keySizeMinValue
{
    return kCCKeySizeMinCAST;
}

+ (NSInteger)keySizeMaxValue
{
    return kCCKeySizeMaxCAST;
}

@end

/*
@implementation ECCipherRC4
 
 + (ECCipherAlgorithm)algorithm
 {
 return ECCipherAlgorithmRC4;
 }
 
 + (NSInteger)blockSize
 {
 return ECCipherBlockSizeNotProvided;
 }


 + (BOOL)validateKeySize:(NSInteger)keySize
 {
    return keySize >= kCCKeySizeMinRC4 && keySize <= kCCKeySizeMaxRC4;
 }
 
 + (NSInteger)keySizeMinValue
 {
 return kCCKeySizeMinRC4;
 }
 
 + (NSInteger)keySizeMaxValue
 {
 return kCCKeySizeMaxRC4;
 }
 
@end
 */

@implementation ECCipherRC2

+ (ECCipherAlgorithm)algorithm
{
    return ECCipherAlgorithmRC2;
}

+ (NSInteger)blockSize
{
    return kCCBlockSizeRC2;
}

+ (BOOL)validateKeySize:(NSInteger)keySize
{
    return keySize >= kCCKeySizeMinRC2 && keySize <= kCCKeySizeMaxRC2;
}

+ (NSInteger)keySizeMinValue
{
    return kCCKeySizeMinRC2;
}

+ (NSInteger)keySizeMaxValue
{
    return kCCKeySizeMaxRC2;
}

@end

@implementation ECCipherBlowfish

+ (ECCipherAlgorithm)algorithm
{
    return ECCipherAlgorithmBlowfish;
}

+ (NSInteger)blockSize
{
    return kCCBlockSizeBlowfish;
}

+ (BOOL)validateKeySize:(NSInteger)keySize
{
    return keySize >= kCCKeySizeMinBlowfish && keySize <= kCCKeySizeMaxBlowfish;
}

+ (NSInteger)keySizeMinValue
{
    return kCCKeySizeMinBlowfish;
}

+ (NSInteger)keySizeMaxValue
{
    return kCCKeySizeMaxBlowfish;
}

@end
