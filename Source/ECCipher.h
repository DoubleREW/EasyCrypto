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
    ECCipherAlgorithmDES,
    ECCipherAlgorithm3DES,
    ECCipherAlgorithmCAST,
    ECCipherAlgorithmRC2,
    ECCipherAlgorithmBlowfish
};

typedef NS_ENUM(NSUInteger, ECCipherMode) {
    ECCipherModeECB = 1,
    ECCipherModeCBC,
    ECCipherModeCFB,
    ECCipherModeCTR,
    ECCipherModeOFB,
    ECCipherModeXTS,
    ECCipherModeRC4,
    ECCipherModeCFB8
};

typedef NS_ENUM(NSUInteger, ECCipherPadding) {
    ECCipherPaddingNone			= 0,
    ECCipherPaddingPKCS7		= 1,
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
@property (nonatomic, readonly) ECCipherMode mode;
@property (nonatomic, readonly) ECCipherPadding padding;
@property (nonatomic, readonly) NSInteger blockSize; // Byte
@property (nonatomic, readonly) NSInteger keySize; // Byte
@property (nonatomic, readonly, nonnull) NSData *key;
@property (nonatomic, readonly, nullable) NSData *iv; // Initilization Vector ([iv length] == [blockSize length])

// Se iv==nil verrà usato un array di bytes nulli
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key; // option=CBCModeNoPadding, iv=nil
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key iv:(nullable NSData *)iv; // option=CBCModeNoPadding
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key mode:(ECCipherMode)mode; // iv=nil
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key mode:(ECCipherMode)mode padding:(ECCipherPadding)padding iv:(nullable NSData *)iv;

- (nonnull instancetype)initWithStringKey:(nonnull NSString *)key; // mode=cbc, padding=none, iv=nil
- (nonnull instancetype)initWithStringKey:(nonnull NSString *)key iv:(nullable NSData *)iv; // mode=cbc, padding=none
- (nonnull instancetype)initWithStringKey:(nonnull NSString *)key mode:(ECCipherMode)mode; // padding=none, iv=nil
- (nonnull instancetype)initWithStringKey:(nonnull NSString *)key mode:(ECCipherMode)mode padding:(ECCipherPadding)padding iv:(nullable NSData *)iv;


- (nullable ECCipherEncryptedData *)encryptData:(nonnull NSData *)data error:(NSError * _Nullable * _Nullable)error;
- (nullable ECCipherEncryptedData *)encryptString:(nonnull NSString *)str error:(NSError * _Nullable * _Nullable)error;
- (nullable ECCipherEncryptedData *)encrypt:(nonnull NSString *)str error:(NSError * _Nullable * _Nullable)error;  // Shortcut for encryptString:

- (nullable ECCipherPlainData *)decryptData:(nonnull NSData *)data error:(NSError * _Nullable * _Nullable)error;
- (nullable ECCipherPlainData *)decrypt:(nonnull ECCipherEncryptedData *)data error:(NSError * _Nullable * _Nullable)error;


+ (ECCipherAlgorithm)algorithm;
+ (NSInteger)blockSize;

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
@interface ECCipherRC4 : ECCipher <ECCipherVariableKeySizeAlgorithm>
@end
*/

@interface ECCipherRC2 : ECCipher <ECCipherVariableKeySizeAlgorithm>
@end

@interface ECCipherBlowfish : ECCipher <ECCipherVariableKeySizeAlgorithm>
@end
