#import "RNOMEMOCipher.h"
#import <React/RCTLog.h>

@implementation RNOMEMOCipher

// To export a module named RNOMEMOCipher
RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(addEvent:(NSString *)name location:(NSString *)location)
{
    RCTLogInfo(@"Pretending to create an event %@ at %@", name, location);
}


@end
