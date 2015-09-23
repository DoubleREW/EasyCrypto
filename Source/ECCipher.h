//
//  ECCipher.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>


@class ECCipherPlainData, ECCipherEncryptedData;

extern NSString * _Nonnull const ECCipherError;
extern NSInteger ECCipherEncryptionError;
extern NSInteger ECCipherDecryptionError;


typedef NS_ENUM(NSUInteger, ECCipherAlgorithm) {
    ECCipherAlgorithmAES128     = 0,
    ECCipherAlgorithmAES        = 0,
    ECCipherAlgorithmDES        = 1,
    ECCipherAlgorithm3DES       = 2,
    ECCipherAlgorithmCAST       = 3,
    ECCipherAlgorithmRC4        = 4,
    ECCipherAlgorithmRC2        = 5,
    ECCipherAlgorithmBlowfish   = 6
};

typedef NS_ENUM(NSUInteger, ECCipherOption) {
    ECCipherOptionCBCModeNoPadding     = 0x0000, // CBC mode, no padding
    ECCipherOptionCBCModePKCS7Padding  = 0x0001, // CBC mode, PKCS7 padding
    ECCipherOptionECBModeNoPadding     = 0x0002, // ECB mode, no padding
    ECCipherOptionECBModePKCS7Padding  = 0x0003,  // ECB mode, PKCS7 padding
    
    ECCipherOptionDefault  = ECCipherOptionCBCModeNoPadding  // Default option
};

typedef NS_ENUM(NSUInteger, ECCipherKeySize) {
    ECCipherKeySizeAES128          = 16,
    ECCipherKeySizeAES192          = 24,
    ECCipherKeySizeAES256          = 32,
    ECCipherKeySizeDES             = 8,
    ECCipherKeySize3DES            = 24,
    ECCipherKeySizeMinCAST         = 5,
    ECCipherKeySizeMaxCAST         = 16,
    // ECCipherKeySizeMinRC4       = 1,
    // ECCipherKeySizeMaxRC4       = 512,
    ECCipherKeySizeMinRC2          = 1,
    ECCipherKeySizeMaxRC2          = 128,
    ECCipherKeySizeMinBlowfish     = 8,
    ECCipherKeySizeMaxBlowfish     = 56,
};

typedef NS_ENUM(NSUInteger, ECCipherBlockSize) {
    /* AES */
    ECCipherBlockSizeAES128        = 16,
    /* DES */
    ECCipherBlockSizeDES           = 8,
    /* 3DES */
    ECCipherBlockSize3DES          = 8,
    /* CAST */
    ECCipherBlockSizeCAST          = 8,
    ECCipherBlockSizeRC2           = 8,
    ECCipherBlockSizeBlowfish      = 8,
};

@protocol ECCipherVariableKeySizeAlgorithm <NSObject>

+ (NSInteger)keySizeMinValue;
+ (NSInteger)keySizeMaxValue;

@end

@protocol ECCipherFixedKeySizeAlgorithm <NSObject>

+ (nonnull NSArray<NSNumber *> *)keySizes;

@end

@interface ECCipher : NSObject

@property (nonatomic, readonly) ECCipherAlgorithm algorithm;
@property (nonatomic, readonly) ECCipherBlockSize blockSize; // Byte
@property (nonatomic, readonly) ECCipherOption option;
@property (nonatomic, readonly) NSInteger keySize; // Byte
@property (nonatomic, readonly, nonnull) NSData *key;
@property (nonatomic, readonly, nullable) NSData *iv; // Initilization Vector ([iv length] == [blockSize length])

// Se iv==nil verrà usato un array di bytes nulli
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key; // option=CBCModeNoPadding, iv=nil
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key iv:(nullable NSData *)iv; // option=CBCModeNoPadding
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key option:(ECCipherOption)opt; // iv=nil
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key option:(ECCipherOption)opt iv:(nullable NSData *)iv;

- (nonnull instancetype)initWithStringKey:(nonnull NSString *)key; // option=CBCModeNoPadding, iv=nil
- (nonnull instancetype)initWithStringKey:(nonnull NSString *)key iv:(nullable NSData *)iv; // option=CBCModeNoPadding
- (nonnull instancetype)initWithStringKey:(nonnull NSString *)key option:(ECCipherOption)opt; // iv=nil
- (nonnull instancetype)initWithStringKey:(nonnull NSString *)key option:(ECCipherOption)opt iv:(nullable NSData *)iv;


- (nullable ECCipherEncryptedData *)encryptData:(nonnull NSData *)data error:(NSError * _Nullable * _Nullable)error;
- (nullable ECCipherEncryptedData *)encryptString:(nonnull NSString *)str error:(NSError * _Nullable * _Nullable)error;
- (nullable ECCipherEncryptedData *)encrypt:(nonnull NSString *)str error:(NSError * _Nullable * _Nullable)error;  // Shortcut for encryptString:

- (nullable ECCipherPlainData *)decryptData:(nonnull NSData *)data error:(NSError * _Nullable * _Nullable)error;
- (nullable ECCipherPlainData *)decrypt:(nonnull ECCipherEncryptedData *)data error:(NSError * _Nullable * _Nullable)error;

+ (BOOL)validateDataKey:(nonnull NSData *)key;
+ (BOOL)validateStringKey:(nonnull NSString *)key;
+ (BOOL)validateKey:(nonnull NSString *)key;

@end

@interface ECCipherAES : ECCipher <ECCipherFixedKeySizeAlgorithm>
@end

@interface ECCipherDES : ECCipher <ECCipherFixedKeySizeAlgorithm>
@end

@interface ECCipher3DES : ECCipher <ECCipherFixedKeySizeAlgorithm>
@end

@interface ECCipherCAST : ECCipher <ECCipherVariableKeySizeAlgorithm>
@end

/*
@interface ECCipherRC4 : ECCipher
@end
*/

@interface ECCipherRC2 : ECCipher <ECCipherVariableKeySizeAlgorithm>
@end

@interface ECCipherBlowfish : ECCipher <ECCipherVariableKeySizeAlgorithm>
@end
