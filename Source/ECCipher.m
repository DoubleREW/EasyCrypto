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


@interface ECCipher ()

@property (nonatomic, assign) ECCipherAlgorithm algorithm;
@property (nonatomic, assign) ECCipherBlockSize blockSize;
@property (nonatomic, assign) ECCipherOption option;
@property (nonatomic, assign) ECCipherKeySize keySize;
@property (nonatomic, strong) NSData *key;
@property (nonatomic, strong) NSData *iv;

- (BOOL)checkKeySize:(ECCipherKeySize)keySize;

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

- (instancetype)initWithDataKey:(NSData *)key option:(ECCipherOption)opt keySize:(ECCipherKeySize)keySize iv:(NSData *)iv;
{
    self = [self init];
    if (self) {
        if (iv != nil)
            NSAssert2([self blockSize] == [iv length], @"The inizialization vector's length must be equal to the algorithm's block size (%ld != %ld).", [iv length], [self blockSize]);
        
        NSAssert1([self checkKeySize:keySize], @"The chosen key size (%ld) is not valid for this algorithm.", keySize);
        
        _key = key;
        _option = opt;
        _iv = iv;
        _keySize = keySize;
    }
    
    return self;
}

- (instancetype)initWithStringKey:(NSString *)key option:(ECCipherOption)opt keySize:(ECCipherKeySize)keySize iv:(NSData *)iv;
{
    return [self initWithDataKey:[key dataUsingEncoding:NSUTF8StringEncoding]
                          option:opt
                         keySize:keySize
                              iv:iv];
}

- (BOOL)checkKeySize:(ECCipherKeySize)keySize
{
    return NO;
}

- (ECCipherEncryptedData *)encryptData:(NSData *)data error:(NSError **)error;
{
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[self.keySize+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [self.key getBytes:keyPtr length:sizeof(keyPtr)];
    
    NSUInteger dataLength = [data length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + self.blockSize;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, self.algorithm, self.option,
                                          keyPtr, self.keySize,
                                          (self.iv ? [self.iv bytes] : NULL) /* iv (optional) */,
                                          [data bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        NSData *encryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        return [[ECCipherEncryptedData alloc] initWithData:encryptedData];
    }
    
    free(buffer); //free the buffer;
    
    if (error) {
        *error = [NSError errorWithDomain:ECCipherError
                                     code:ECCipherEncryptionError
                                 userInfo:@{NSLocalizedDescriptionKey: GetCCCryptorStatusString(cryptStatus)}];
    }
    
    return nil;
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
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [self.key getBytes:keyPtr length:sizeof(keyPtr)];
    
    NSUInteger dataLength = [data length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + self.blockSize;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, self.algorithm, self.option,
                                          keyPtr, self.keySize,
                                          (self.iv ? [self.iv bytes] : NULL) /* iv (optional) */,
                                          [data bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        NSData *decryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
        return [[ECCipherPlainData alloc] initWithData:decryptedData];
    }
    
    free(buffer); //free the buffer;
    
    if (error) {
        *error = [NSError errorWithDomain:ECCipherError
                                     code:ECCipherDecryptionError
                                 userInfo:@{NSLocalizedDescriptionKey: GetCCCryptorStatusString(cryptStatus)}];
    }
    
    return nil;
}

- (ECCipherPlainData *)decrypt:(ECCipherEncryptedData *)encryptedData error:(NSError **)error
{
    return [self decryptData:encryptedData.rawData error:error];
}

@end

// MARK: Implementations
@implementation ECCipherAES

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.algorithm = ECCipherAlgorithmAES;
        self.blockSize = ECCipherBlockSizeAES128;
    }
    
    return self;
}

- (BOOL)checkKeySize:(ECCipherKeySize)keySize
{
    return keySize == ECCipherKeySizeAES128 || keySize == ECCipherKeySizeAES192 || keySize == ECCipherKeySizeAES256;
}

@end

@implementation ECCipherDES

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.algorithm = ECCipherAlgorithmDES;
        self.blockSize = ECCipherBlockSizeDES;
    }
    
    return self;
}

- (BOOL)checkKeySize:(ECCipherKeySize)keySize
{
    return keySize == ECCipherKeySizeDES;
}

@end

@implementation ECCipher3DES

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.algorithm = ECCipherAlgorithm3DES;
        self.blockSize = ECCipherBlockSize3DES;
    }
    
    return self;
}

- (BOOL)checkKeySize:(ECCipherKeySize)keySize
{
    return keySize == ECCipherKeySize3DES;
}

@end

@implementation ECCipherCAST

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.algorithm = ECCipherAlgorithmCAST;
        self.blockSize = ECCipherBlockSizeCAST;
    }
    
    return self;
}

- (BOOL)checkKeySize:(ECCipherKeySize)keySize
{
    return keySize == ECCipherKeySizeMinCAST || keySize == ECCipherKeySizeMaxCAST;
}

@end

/*
@implementation ECCipherRC4

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.algorithm = ECCipherAlgorithmRC4;
        self.blockSize = ECCipherBlockSizeRC4;
    }
    
    return self;
}

- (BOOL)checkKeySize:(ECCipherKeySize)keySize
{
    return keySize == ECCipherKeySizeMinRC4 || keySize == ECCipherKeySizeMaxRC4;
}

@end
 */

@implementation ECCipherRC2

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.algorithm = ECCipherAlgorithmRC2;
        self.blockSize = ECCipherBlockSizeRC2;
    }
    
    return self;
}

- (BOOL)checkKeySize:(ECCipherKeySize)keySize
{
    return keySize == ECCipherKeySizeMinRC2 || keySize == ECCipherKeySizeMaxRC2;
}

@end

@implementation ECCipherBlowfish

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.algorithm = ECCipherAlgorithmBlowfish;
        self.blockSize = ECCipherBlockSizeBlowfish;
    }
    
    return self;
}

- (BOOL)checkKeySize:(ECCipherKeySize)keySize
{
    return keySize == ECCipherKeySizeMinBlowfish || keySize == ECCipherKeySizeMaxBlowfish;
}

@end
