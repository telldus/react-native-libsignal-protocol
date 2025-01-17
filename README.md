
# react-native-omemo-cipher

## Getting started

`$ npm install react-native-omemo-cipher --save`

For RN >= 60, no explicit linking required, auto linking should work.

### Mostly automatic installation (RN < 60)

`$ react-native link react-native-omemo-cipher`

### Manual installation (RN < 60)


#### iOS

1. In XCode, in the project navigator, right click `Libraries` ➜ `Add Files to [your project's name]`
2. Go to `node_modules` ➜ `react-native-omemo-cipher` and add `RNOMEMOCipher.xcodeproj`
3. In XCode, in the project navigator, select your project. Add `libRNOMEMOCipher.a` to your project's `Build Phases` ➜ `Link Binary With Libraries`
4. Run your project (`Cmd+R`)<

#### Android

1. Open up `android/app/src/main/java/[...]/MainActivity.java`
  - Add `import com.reactlibrary.RNOMEMOCipherPackage;` to the imports at the top of the file
  - Add `new RNOMEMOCipherPackage()` to the list returned by the `getPackages()` method
2. Append the following lines to `android/settings.gradle`:
  	```
  	include ':react-native-omemo-cipher'
  	project(':react-native-omemo-cipher').projectDir = new File(rootProject.projectDir, 	'../node_modules/react-native-omemo-cipher/android')
  	```
3. Insert the following lines inside the dependencies block in `android/app/build.gradle`:
  	```
      compile project(':react-native-omemo-cipher')
  	```

## Usage
```javascript

import {
  generateIdentityKeyPair,
  encryptOMEMO,
  decryptOMEMO,
} from 'react-native-omemo-cipher';

```
  
