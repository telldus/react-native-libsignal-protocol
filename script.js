#!/usr/bin/env node

let fs            = require('fs');
let child_process = require('child_process');
const fsExtra = require('fs-extra');

try {
  console.log('Running postinstall script...');
  process.chdir('./node_modules/react-native-omemo-cipher');

  let exists = fs.existsSync('./libsignal-protocol-c');

  if (exists) {
    fsExtra.emptyDirSync('./libsignal-protocol-c');
    installRepo();
  } else {
    installRepo();
  }

  function installRepo () {
    console.info('check out from github');
    child_process.execSync('git clone https://github.com/signalapp/libsignal-protocol-c.git');
    process.chdir('./libsignal-protocol-c');
    child_process.execSync('git submodule init'); // only needed the first time
  }

  child_process.execSync('git submodule update');

  console.info('installing...');
}
catch (error) {
  console.error('\n\x1b[41mError:\x1b[0m Could not complete the postinstall script.');
  return;
}