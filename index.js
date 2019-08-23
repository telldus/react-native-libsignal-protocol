/**
 * Copyright 2016-present Telldus Technologies AB.
 *
 * This file is part of the Telldus NiceNeighbourApp app.
 *
 * Telldus NiceNeighbourApp app is free : you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Telldus NiceNeighbourApp app is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Telldus NiceNeighbourApp app.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @format
 * @flow
 */

'use strict';

import { NativeModules } from 'react-native';
const { RNLibsignalProtocol } = NativeModules;

export type IdentityKeyPair = {
    serializedKP: string, // Base64 encoded
};
export type Bundle = {
    preKeyId: number,
    registrationId: number,
    preKeyPublic: string, // Base64 encoded string
    signedPreKeyId: number,
    signedPreKeyPublic: string, // Base64 encoded string
    signedPreKeySignature: string, // Base64 encoded string
    identityKey: string, // Base64 encoded string
};
export type DeviceIdBundle = {
    deviceId: string,
    bundle: Bundle,
};
export type DeviceListAndBundle = Array<DeviceIdBundle>;

// Signal Protocol

const generateRegistrationId = (): Promise<any> => {
	return RNLibsignalProtocol.generateRegistrationId();
};

const generateIdentityKeyPair = (): Promise<any> => {
	return RNLibsignalProtocol.generateIdentityKeyPair();
};

const generatePreKeys = (startId: number, count: number): Promise<any> => {
	return RNLibsignalProtocol.generatePreKeys(startId, count);
};

const generateSignedPreKey = (identityKeyPair: IdentityKeyPair, signedKeyId: number): Promise<any> => {
	return RNLibsignalProtocol.generateSignedPreKey(identityKeyPair, signedKeyId);
};

const buildSession = (recipientId: string, deviceListAndBundle: DeviceListAndBundle): Promise<any> => {
	return RNLibsignalProtocol.buildSession(recipientId, deviceListAndBundle);
};

const loadPreKeys = (): Promise<any> => {
	return RNLibsignalProtocol.loadPreKeys();
};

const encryptSignalProtocol = (message: string, recipientId: string, deviceId: number): Promise<any> => {
	return RNLibsignalProtocol.encryptSignalProtocol(message, recipientId, deviceId);
};
// encryptedMessage: Base64 encoded string.
const decryptSignalProtocol = (encryptedMessage: string, recipientId: string, deviceId: number): Promise<any> => {
	return RNLibsignalProtocol.decryptSignalProtocol(encryptedMessage, recipientId, deviceId);
};

export type KeysInfo = {
    deviceId: string,
    prekey: boolean,
    key: string, // Base64 encoded strig.
};
export type KeysList = Array<KeysInfo>;

// OMEMO

const encryptOMEMO = (ownId: string, ownDeviceId: string, recipientId: string, recepientDeviceList: Array<string>, message: string): Promise<any> => {
	return RNLibsignalProtocol.encryptOMEMO(ownId, ownDeviceId, recipientId, recepientDeviceList, message);
};
// iV: Base64 encoded string.
// encryptedMessage: Base64 encoded string.
const decryptOMEMO = (recipientId: string, ownDeviceId: string, iV: string, keysList: KeysList, encryptedMessage: string): Promise<any> => {
	return RNLibsignalProtocol.decryptOMEMO(recipientId, ownDeviceId, iV, keysList, encryptedMessage);
};

module.exports = {
	generateRegistrationId,
	generateIdentityKeyPair,
	generatePreKeys,
	generateSignedPreKey,
	buildSession,
	encryptSignalProtocol,
	decryptSignalProtocol,

	loadPreKeys,

	encryptOMEMO,
	decryptOMEMO,
};
