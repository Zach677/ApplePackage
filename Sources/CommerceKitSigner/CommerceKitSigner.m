#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>

// CommerceKit signing flow adapted from ipatool. See the repository NOTICE.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#import "CommerceKitSigner.h"

@interface APCKSigningSession : NSObject
- (instancetype)initWithStoreClient:(id)storeClient;
- (void)openSessionWithCompletionHandler:(void (^)(void))completionHandler;
- (NSData *)signData:(NSData *)data error:(NSError **)error;
- (void)closeSession;
- (BOOL)isSessionOpen;
@end

static void *commerceKitHandle;
static char commerceKitLoadError[512];

static void APLoadCommerceKit(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        commerceKitHandle = dlopen(
            "/System/Library/PrivateFrameworks/CommerceKit.framework/CommerceKit",
            RTLD_LAZY | RTLD_LOCAL
        );
        if (commerceKitHandle == NULL) {
            const char *message = dlerror();
            snprintf(
                commerceKitLoadError,
                sizeof(commerceKitLoadError),
                "%s",
                message != NULL ? message : "failed to load CommerceKit"
            );
        }
    });
}

static void APSetError(char **destination, const char *message) {
    if (destination != NULL) {
        *destination = strdup(message != NULL ? message : "unknown CommerceKit error");
    }
}

static void APSetNSError(char **destination, NSError *error, const char *fallback) {
    const char *message = error.localizedDescription.UTF8String;
    APSetError(destination, message != NULL ? message : fallback);
}

int APCommerceKitSign(
    const unsigned char *input,
    size_t inputLength,
    unsigned char **output,
    size_t *outputLength,
    char **errorMessage
) {
    if (output == NULL || outputLength == NULL || (input == NULL && inputLength > 0)) {
        APSetError(errorMessage, "invalid action signing parameters");
        return 2;
    }

    *output = NULL;
    *outputLength = 0;
    if (errorMessage != NULL) {
        *errorMessage = NULL;
    }

    @autoreleasepool {
        APLoadCommerceKit();
        if (commerceKitHandle == NULL) {
            APSetError(errorMessage, commerceKitLoadError);
            return 1;
        }

        Class signingSessionClass = NSClassFromString(@"CKSigningSession");
        if (signingSessionClass == Nil) {
            APSetError(errorMessage, "CKSigningSession is missing from CommerceKit");
            return 1;
        }
        if (![signingSessionClass instancesRespondToSelector:@selector(initWithStoreClient:)] ||
            ![signingSessionClass instancesRespondToSelector:@selector(openSessionWithCompletionHandler:)] ||
            ![signingSessionClass instancesRespondToSelector:@selector(signData:error:)] ||
            ![signingSessionClass instancesRespondToSelector:@selector(closeSession)]) {
            APSetError(errorMessage, "CKSigningSession does not support the required signing methods");
            return 1;
        }

        APCKSigningSession *session = [(id)[signingSessionClass alloc] initWithStoreClient:nil];
        if (session == nil) {
            APSetError(errorMessage, "CommerceKit could not create a signing session");
            return 2;
        }

        dispatch_semaphore_t opened = dispatch_semaphore_create(0);
        [session openSessionWithCompletionHandler:^{
            dispatch_semaphore_signal(opened);
        }];

        long waitResult = dispatch_semaphore_wait(
            opened,
            dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC)
        );
        if (waitResult != 0) {
            [session closeSession];
            APSetError(errorMessage, "timed out opening the Apple signing session");
            return 2;
        }

        if ([session respondsToSelector:@selector(isSessionOpen)] && ![session isSessionOpen]) {
            [session closeSession];
            APSetError(errorMessage, "Apple signing session did not open");
            return 2;
        }

        NSData *data = [NSData dataWithBytes:input length:inputLength];
        NSError *signingError = nil;
        NSData *signature = [session signData:data error:&signingError];
        [session closeSession];

        if (signature == nil || signature.length == 0) {
            APSetNSError(errorMessage, signingError, "CommerceKit returned an empty signature");
            return 2;
        }

        unsigned char *signatureCopy = malloc(signature.length);
        if (signatureCopy == NULL) {
            APSetError(errorMessage, "failed to allocate the Apple action signature");
            return 2;
        }

        [signature getBytes:signatureCopy length:signature.length];
        *output = signatureCopy;
        *outputLength = signature.length;
        return 0;
    }
}
