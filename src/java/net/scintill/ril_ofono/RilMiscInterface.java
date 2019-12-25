/*
 * Copyright 2017 Joey Hewitt <joey@joeyhewitt.com>
 *
 * This file is part of ril_ofono.
 *
 * ril_ofono is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ril_ofono is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ril_ofono.  If not, see <http://www.gnu.org/licenses/>.
 */

package net.scintill.ril_ofono;

import android.telephony.data.DataProfile;

import com.android.internal.telephony.cdma.CdmaSmsBroadcastConfigInfo;
import com.android.internal.telephony.gsm.SmsBroadcastConfigInfo;

interface RilMiscInterface {
    Object getImsRegistrationState();

    Object setSuppServiceNotifications(boolean enable);

    Object supplyIccPin(String pin);

    Object supplyIccPinForApp(String pin, String aid);

    Object supplyIccPuk(String puk, String newPin);

    Object supplyIccPukForApp(String puk, String newPin, String aid);

    Object supplyIccPin2(String pin2);

    Object supplyIccPin2ForApp(String pin2, String aid);

    Object supplyIccPuk2(String puk2, String newPin2);

    Object supplyIccPuk2ForApp(String puk2, String newPin2, String aid);

    Object changeIccPin(String oldPin, String newPin);

    Object changeIccPinForApp(String oldPin, String newPin, String aidPtr);

    Object changeIccPin2(String oldPin2, String newPin2);

    Object changeIccPin2ForApp(String oldPin2, String newPin2, String aidPtr);

    Object changeBarringPassword(String facility, String oldPwd, String newPwd);

    Object supplyNetworkDepersonalization(String netpin);

    Object getPDPContextList();

    Object getDataCallProfile(int appType);

    Object setDataProfile(DataProfile[] dps, boolean isRoaming);

    Object hangupForegroundResumeBackground();

    Object switchWaitingOrHoldingAndActive();

    Object conference();

    Object setPreferredVoicePrivacy(boolean enable);

    Object getPreferredVoicePrivacy();

    Object separateConnection(int gsmIndex);

    Object explicitCallTransfer();

    Object getLastCallFailCause();

    Object getLastPdpFailCause();

    Object getLastDataCallFailCause();

    Object setMute(boolean enableMute);

    Object getMute();

    Object sendBurstDtmf(String dtmfString, int on, int off);

    Object sendSMSExpectMore(String smscPDU, String pdu);

    Object sendCdmaSms(byte[] pdu);

    Object sendImsGsmSms(String smscPDU, String pdu, int retry, int messageRef);

    Object sendImsCdmaSms(byte[] pdu, int retry, int messageRef);

    Object deleteSmsOnSim(int index);

    Object deleteSmsOnRuim(int index);

    Object writeSmsToSim(int status, String smsc, String pdu);

    Object writeSmsToRuim(int status, String pdu);

    Object acknowledgeLastIncomingGsmSms(boolean success, int cause);

    Object acknowledgeLastIncomingCdmaSms(boolean success, int cause);

    Object acknowledgeIncomingGsmSmsWithPdu(boolean success, String ackPdu);

    Object queryCLIP();

    Object getCLIR();

    Object setCLIR(int clirMode);

    Object queryCallWaiting(int serviceClass);

    Object setCallWaiting(boolean enable, int serviceClass);

    Object setCallForward(int action, int cfReason, int serviceClass, String number, int timeSeconds);

    Object queryCallForwardStatus(int cfReason, int serviceClass, String number);

    Object setNetworkSelectionModeAutomatic();

    Object setNetworkSelectionModeManual(String operatorNumeric);

    Object getAvailableNetworks();

    Object queryFacilityLock(String facility, String password, int serviceClass);

    Object queryFacilityLockForApp(String facility, String password, int serviceClass, String appId);

    Object setFacilityLock(String facility, boolean lockState, String password, int serviceClass);

    Object setFacilityLockForApp(String facility, boolean lockState, String password, int serviceClass, String appId);

    Object cancelPendingUssd();

    Object resetRadio();

    Object setBandMode(int bandMode);

    Object queryAvailableBandMode();

    Object setPreferredNetworkType(int networkType);

    Object getPreferredNetworkType();

    Object getNeighboringCids();

    Object setLocationUpdates(boolean enable);

    Object getSmscAddress();

    Object setSmscAddress(String address);

    Object reportSmsMemoryStatus(boolean available);

    Object reportStkServiceIsRunning();

    Object invokeOemRilRequestRaw(byte[] data);

    Object invokeOemRilRequestStrings(String[] strings);

    Object sendTerminalResponse(String contents);

    Object sendEnvelope(String contents);

    Object sendEnvelopeWithStatus(String contents);

    Object handleCallSetupRequestFromSim(boolean accept);

    Object setGsmBroadcastActivation(boolean activate);

    Object setGsmBroadcastConfig(SmsBroadcastConfigInfo[] config);

    Object getGsmBroadcastConfig();

    Object getDeviceIdentity();

    Object getCDMASubscription();

    Object sendCDMAFeatureCode(String FeatureCode);

    Object queryCdmaRoamingPreference();

    Object setCdmaRoamingPreference(int cdmaRoamingType);

    Object setCdmaSubscriptionSource(int cdmaSubscriptionType);

    Object getCdmaSubscriptionSource();

    Object setTTYMode(int ttyMode);

    Object queryTTYMode();

    Object setCdmaBroadcastActivation(boolean activate);

    Object setCdmaBroadcastConfig(CdmaSmsBroadcastConfigInfo[] configs);

    Object getCdmaBroadcastConfig();

    Object exitEmergencyCallbackMode();

    Object requestIsimAuthentication(String nonce);

    Object requestIccSimAuthentication(int authContext, String data, String aid);

    Object getCellInfoList();

    Object setCellInfoListRate(int rateInMillis);

    Object nvReadItem(int itemID);

    Object nvWriteItem(int itemID, String itemValue);

    Object nvWriteCdmaPrl(byte[] preferredRoamingList);

    Object nvResetConfig(int resetType);

    Object getHardwareConfig();
}
