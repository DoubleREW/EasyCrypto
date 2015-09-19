//
//  EasyCrypto.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 15/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>


//! Project version number for EasyCrypto.
FOUNDATION_EXPORT double EasyCryptoVersionNumber;

//! Project version string for EasyCrypto.
FOUNDATION_EXPORT const unsigned char EasyCryptoVersionString[];
//#endif

// In this header, you should import all the public headers of your framework using statements like #import <EasyCrypto/PublicHeader.h>
#if !TARGET_OS_IPHONE
#import <EasyCrypto/ECRsaSignature.h>
#import <EasyCrypto/ECRsaKey.h>
#import <EasyCrypto/ECRsaKeyPair.h>
#import <EasyCrypto/ECRsa.h>
#endif

#import <EasyCrypto/ECHash.h>
#import <EasyCrypto/ECHmac.h>
#import <EasyCrypto/ECHashExtensions.h>

#import <EasyCrypto/ECCipher.h>
#import <EasyCrypto/ECCipherData.h>