//
//  ECCipher.m
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECCipher.h"
#import "ECCipher+Private.h"


@interface ECCipher ()

@property (nonatomic, assign) ECCipherAlgorithm algorithm;
@property (nonatomic, assign) ECCipherBlockSize blockSize;
@property (nonatomic, assign) ECCipherOption option;
@property (nonatomic, assign) ECCipherKeySize keySize;
@property (nonatomic, strong) NSData *key;
@property (nonatomic, strong) NSData *iv;

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
        
        _key = key;
        _option = opt;
        _keySize = keySize;
        _iv = iv;
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

- (NSData *)encryptData:(NSData *)data
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
                                          NULL /* initialization vector (optional) */,
                                          [data bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
}

- (NSData *)encryptString:(NSString *)str
{
    return [self encryptData:[str dataUsingEncoding:NSUTF8StringEncoding]];
}

- (NSData *)encrypt:(NSString *)str
{
    return [self encryptString:str];
}

- (NSData *)decrypt:(NSData *)data
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
                                          NULL /* initialization vector (optional) */,
                                          [data bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
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

@end
