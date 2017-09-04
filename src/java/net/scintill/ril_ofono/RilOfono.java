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

import android.os.AsyncResult;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.os.StrictMode;
import android.telephony.Rlog;
import android.text.TextUtils;

import com.android.internal.telephony.CommandException;
import com.android.internal.telephony.cdma.CdmaSmsBroadcastConfigInfo;
import com.android.internal.telephony.dataconnection.DataProfile;
import com.android.internal.telephony.gsm.SmsBroadcastConfigInfo;
import com.android.internal.telephony.uicc.IccIoResult;
import com.android.internal.telephony.uicc.IccUtils;

import org.freedesktop.dbus.DBusConnection;
import org.freedesktop.dbus.DBusInterface;
import org.freedesktop.dbus.DBusSigHandler;
import org.freedesktop.dbus.DBusSignal;
import org.freedesktop.dbus.exceptions.DBusException;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static com.android.internal.telephony.CommandException.Error.REQUEST_NOT_SUPPORTED;
import static com.android.internal.telephony.CommandsInterface.RadioState;

public class RilOfono implements RilMiscInterface {

    /*package*/ static final String TAG = "RilOfono";
    private static final int BUILD_NUMBER = 12;
    /*package*/ static final boolean LOG_POTENTIALLY_SENSITIVE_INFO = true;

    private static final String DBUS_ADDRESS = "unix:path=/dev/socket/dbus";

    private RilWrapperBase mRilWrapper;
    private Handler mDbusHandler;
    private Handler mMainHandler;

    private DBusConnection mDbus;

    /*package*/ static RilOfono sInstance;

    /*package*/ RilOfono(final RilWrapperBase rilWrapper) {
        sInstance = this;
        Rlog.d(TAG, "RilOfono "+BUILD_NUMBER+" starting");

        mRilWrapper = rilWrapper;

        HandlerThread dbusThread = new HandlerThread("RilOfonoDbusThread");
        dbusThread.start();
        mMainHandler = new Handler(new EmptyHandlerCallback());
        mDbusHandler = new Handler(dbusThread.getLooper(), new EmptyHandlerCallback());

        // We can't really return until the objects below are created
        // (otherwise calls start coming in while we have null pointers), and the objects need dbus,
        // so this is one time we'll allow network on main.
        runWithNetworkPermittedOnMainThread(new Runnable() {
            @Override
            public void run() {
                try {
                    mDbus = DBusConnection.getConnection(DBUS_ADDRESS);

                    mRilWrapper.mMiscModule = RilOfono.this;
                    mRilWrapper.mModemModule = new ModemModule(mRilWrapper.mVoiceNetworkStateRegistrants, mRilWrapper.mVoiceRadioTechChangedRegistrants, mRilWrapper.mSignalStrengthRegistrants);
                    mRilWrapper.mSmsModule = new SmsModule(mRilWrapper.mGsmSmsRegistrants); // TODO gsm-specific
                    mRilWrapper.mSimModule = new SimModule(mRilWrapper.mIccStatusChangedRegistrants);
                    mRilWrapper.mVoicecallModule = new VoicecallModule(mRilWrapper.mCallStateRegistrants);
                    mRilWrapper.mDatacallModule = new DatacallModule(mRilWrapper.mDataNetworkStateRegistrants);
                    mRilWrapper.mSupplementaryServicesModule = new SupplementaryServicesModule(mRilWrapper.mUSSDRegistrants);
                    ((ModemModule)mRilWrapper.mModemModule).onModemChange(false); // initialize starting state
                } catch (Throwable t) {
                    throw new RuntimeException("exception while loading", t);
                }
            }
        });
        // TODO register with TelephonyDevController ?

        //mMainHandler.postDelayed(new Tests(mSmsModule), 10000);
    }

    /*package*/ void onModemAvail() {
        // RIL.java for RIL_UNSOL_RIL_CONNECTED does this
        try {
            mRilWrapper.mModemModule.setRadioPower(false);
        } catch (Throwable t) {
            setRadioState(RadioState.RADIO_UNAVAILABLE);
            Rlog.e(TAG, "onModemAvail: setRadioPower(false) threw an exception", t);
            return;
        }

        setRadioState(RadioState.RADIO_OFF);

        // TODO What does this mean to consumers? I picked 9 because it's less than 10, which is
        // apparently when the icc*() methods we won't support were added.
        final int RIL_VERSION = 9;
        mRilWrapper.updateRilConnection(RIL_VERSION);

        // TODO call VoiceManager GetCalls() ? oFono docs on that method suggest you should at startup
    }

    @Override
    @OkOnMainThread
    public Object getImsRegistrationState() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setSuppServiceNotifications(boolean enable) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object supplyIccPin(String pin) {
        return supplyIccPinForApp(pin, null);
    }

    @Override
    @OkOnMainThread
    public Object supplyIccPinForApp(String pin, String aid) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object supplyIccPuk(String puk, String newPin) {
        return supplyIccPukForApp(puk, newPin, null);
    }

    @Override
    @OkOnMainThread
    public Object supplyIccPukForApp(String puk, String newPin, String aid) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object supplyIccPin2(String pin2) {
        return supplyIccPin2ForApp(pin2, null);
    }

    @Override
    @OkOnMainThread
    public Object supplyIccPin2ForApp(String pin2, String aid) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object supplyIccPuk2(String puk2, String newPin2) {
        return supplyIccPuk2ForApp(puk2, newPin2, null);
    }

    @Override
    @OkOnMainThread
    public Object supplyIccPuk2ForApp(String puk2, String newPin2, String aid) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object changeIccPin(String oldPin, String newPin) {
        return changeIccPin2ForApp(oldPin, newPin, null);
    }

    @Override
    @OkOnMainThread
    public Object changeIccPinForApp(String oldPin, String newPin, String aidPtr) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object changeIccPin2(String oldPin2, String newPin2) {
        return changeIccPin2ForApp(oldPin2, newPin2, null);
    }

    @Override
    @OkOnMainThread
    public Object changeIccPin2ForApp(String oldPin2, String newPin2, String aidPtr) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object changeBarringPassword(String facility, String oldPwd, String newPwd) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object supplyDepersonalization(String netpin, String type) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getPDPContextList() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getDataCallProfile(int appType) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setDataProfile(DataProfile[] dps) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object hangupForegroundResumeBackground() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object switchWaitingOrHoldingAndActive() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object conference() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setPreferredVoicePrivacy(boolean enable) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getPreferredVoicePrivacy() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object separateConnection(int gsmIndex) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object explicitCallTransfer() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getLastCallFailCause() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getLastPdpFailCause() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getLastDataCallFailCause() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setMute(boolean enableMute) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getMute() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object sendDtmf(char c) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object startDtmf(char c) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object stopDtmf() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object sendBurstDtmf(String dtmfString, int on, int off) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    public Object sendSMSExpectMore(String smscPDU, String pdu) {
        // TODO can oFono benefit from knowing to "expect more"?
        return mRilWrapper.mSmsModule.sendSMS(smscPDU, pdu);
    }

    @Override
    @OkOnMainThread
    public Object sendCdmaSms(byte[] pdu) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object sendImsGsmSms(String smscPDU, String pdu, int retry, int messageRef) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object sendImsCdmaSms(byte[] pdu, int retry, int messageRef) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object deleteSmsOnSim(int index) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object deleteSmsOnRuim(int index) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object writeSmsToSim(int status, String smsc, String pdu) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object writeSmsToRuim(int status, String pdu) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object acknowledgeLastIncomingGsmSms(boolean success, int cause) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object acknowledgeLastIncomingCdmaSms(boolean success, int cause) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object acknowledgeIncomingGsmSmsWithPdu(boolean success, String ackPdu) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object queryCLIP() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getCLIR() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setCLIR(int clirMode) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object queryCallWaiting(int serviceClass) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setCallWaiting(boolean enable, int serviceClass) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setCallForward(int action, int cfReason, int serviceClass, String number, int timeSeconds) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object queryCallForwardStatus(int cfReason, int serviceClass, String number) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setNetworkSelectionModeAutomatic() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setNetworkSelectionModeManual(String operatorNumeric) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getAvailableNetworks() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object queryFacilityLock(String facility, String password, int serviceClass) {
        return queryFacilityLockForApp(facility, password, serviceClass, null);
    }

    @Override
    @OkOnMainThread
    public Object queryFacilityLockForApp(String facility, String password, int serviceClass, String appId) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setFacilityLock(String facility, boolean lockState, String password, int serviceClass) {
        return setFacilityLockForApp(facility, lockState, password, serviceClass, null);
    }

    @Override
    @OkOnMainThread
    public Object setFacilityLockForApp(String facility, boolean lockState, String password, int serviceClass, String appId) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object cancelPendingUssd() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object resetRadio() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setBandMode(int bandMode) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object queryAvailableBandMode() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setPreferredNetworkType(int networkType) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getPreferredNetworkType() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getNeighboringCids() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setLocationUpdates(boolean enable) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getSmscAddress() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setSmscAddress(String address) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object reportSmsMemoryStatus(boolean available) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object reportStkServiceIsRunning() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object invokeOemRilRequestRaw(byte[] data) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object invokeOemRilRequestStrings(String[] strings) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object sendTerminalResponse(String contents) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object sendEnvelope(String contents) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object sendEnvelopeWithStatus(String contents) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object handleCallSetupRequestFromSim(boolean accept) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setGsmBroadcastActivation(boolean activate) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setGsmBroadcastConfig(SmsBroadcastConfigInfo[] config) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getGsmBroadcastConfig() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getDeviceIdentity() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getCDMASubscription() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object sendCDMAFeatureCode(String FeatureCode) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object queryCdmaRoamingPreference() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setCdmaRoamingPreference(int cdmaRoamingType) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setCdmaSubscriptionSource(int cdmaSubscriptionType) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getCdmaSubscriptionSource() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setTTYMode(int ttyMode) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object queryTTYMode() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setCdmaBroadcastActivation(boolean activate) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setCdmaBroadcastConfig(CdmaSmsBroadcastConfigInfo[] configs) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getCdmaBroadcastConfig() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object exitEmergencyCallbackMode() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object requestIsimAuthentication(String nonce) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object requestIccSimAuthentication(int authContext, String data, String aid) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getCellInfoList() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object setCellInfoListRate(int rateInMillis) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object nvReadItem(int itemID) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object nvWriteItem(int itemID, String itemValue) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object nvWriteCdmaPrl(byte[] preferredRoamingList) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object nvResetConfig(int resetType) {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    @Override
    @OkOnMainThread
    public Object getHardwareConfig() {
        throw new CommandException(REQUEST_NOT_SUPPORTED);
    }

    /*package*/ void setRadioState(RadioState newState) {
        mRilWrapper.setRadioStateHelper(newState);
    }

    // TODO
    // things I noticed BaseCommands overrides but has an empty implementation we might need to override:
    // getModemCapability(),
    // setUiccSubscription(), requestShutdown(),
    // iccOpenLogicalChannel(), iccCloseLogicalChannel(), iccTransmitApduLogicalChannel(),
    // iccTransmitApduBasicChannel(), getAtr(), setLocalCallHold()

    private static final String OFONO_BUS_NAME = "org.ofono";
    private static final String MODEM_PATH = "/gobi_0"; // TODO make this dynamically use the "first" modem we see (because we only expect one)

    /*package*/ <T extends DBusInterface> T getOfonoInterface(Class<T> tClass) {
        return getOfonoInterface(tClass, MODEM_PATH);
    }

    /*package*/ <T extends DBusInterface> T getOfonoInterface(Class<T> tClass, String path) {
        try {
            return mDbus.getRemoteObject(OFONO_BUS_NAME, path, tClass);
        } catch (DBusException e) {
            throw new RuntimeException("Exception getting "+ tClass.getSimpleName(), e);
        }
    }

    // no exception catch-all will be provided
    /*package*/ <T extends DBusSignal> void registerDbusSignal(Class<T> signalClass, DBusSigHandler<T> handler) {
        try {
            mDbus.addSigHandler(signalClass, handler);
        } catch (DBusException e) {
            throw new RuntimeException("Unable to register dbus signal handler", e);
        }
    }

    // an exception catch-all (that logs exceptions with privExc()) will be provided
    /*package*/ <T extends DBusSignal> void registerDbusSignal(Class<T> signalClass, final Object handler) {
        try {
            final Method m = handler.getClass().getMethod("handle", signalClass);
            mDbus.addSigHandler(signalClass, new DBusSigHandler<T>() {
                @Override
                public void handle(T s) {
                    try {
                        m.invoke(handler, s);
                    } catch (IllegalAccessException e) {
                        throw new RuntimeException("Unexpected exception while delegating dbus signal", e);
                    } catch (InvocationTargetException e) {
                        Rlog.e(TAG, "Unexpected exception while dispatching dbus signal", privExc(e.getCause()));
                        // do not re-throw
                    }
                }
            });
        } catch (NoSuchMethodException e) {
            throw new RuntimeException("Unable to find dbus signal handler", e);
        } catch (DBusException e) {
            throw new RuntimeException("Unable to register dbus signal handler", e);
        }
    }

    private class EmptyHandlerCallback implements Handler.Callback {
        @Override
        public boolean handleMessage(Message msg) {
            return true;
        }
    }

    private static final Set<String> quietRespondOk = new HashSet<>(Arrays.asList(new String[]{
        "getSignalStrength", "getBasebandVersion", "getIMSIForApp", "getIccCardStatus", "iccIO", "iccIOForApp"
    }));
    private static final Set<String> quietRespondExc = new HashSet<>(Arrays.asList(new String[]{
        "setCdmaBroadcastActivation", "setCdmaBroadcastConfig",
    }));

    /*package*/ static void respondOk(String caller, Message response, Object o) {
        boolean quiet = quietRespondOk.contains(caller);

        PrivResponseOb privResponseOb = null;
        if (o instanceof PrivResponseOb) {
            privResponseOb = (PrivResponseOb) o;
            o = privResponseOb.o;
        }

        if (!quiet) {
            CharSequence debugString = toDebugString(o, privResponseOb != null);
            Rlog.d(TAG, "respondOk from " + caller + ": " + debugString);
        }
        if (response != null) {
            AsyncResult.forMessage(response, o, null);
            response.sendToTarget();
        }
    }

    /*package*/ static void respondExc(String caller, Message response, CommandException exc, Object o) {
        boolean quiet = quietRespondExc.contains(caller);

        PrivResponseOb privResponseOb = null;
        if (o instanceof PrivResponseOb) {
            privResponseOb = (PrivResponseOb) o;
            o = privResponseOb.o;
        }

        if (!quiet) {
            CharSequence debugString = toDebugString(o, privResponseOb != null);
            Rlog.d(TAG, "respondExc from "+caller+": "+exc.getCommandError()+" "+debugString);
        }
        if (response != null) {
            AsyncResult.forMessage(response, o, exc);
            response.sendToTarget();
        }
    }

    /*package*/ static void notifyResultAndLog(String logSuffix, RegistrantList list, Object result, boolean priv) {
        Rlog.i(TAG, "notify "+logSuffix+" "+(priv ? privStr("") : toDebugString(result)));
        list.notifyResult(result);
    }

    private static void postDebounced(Handler h, DebouncedRunnable r, long delayMillis) {
        //noinspection SynchronizationOnLocalVariableOrMethodParameter
        synchronized (h) {
            if (!h.hasCallbacks(r)) {
                h.sendMessageDelayed(Message.obtain(h, r), delayMillis);
            }
        }
    }

    /*package*/ static void runOnDbusThread(Runnable r) {
        sInstance.mDbusHandler.post(r);
    }

    // We often won't care much what thread it runs on, but in order to use a Handler, I guess we need
    // to specify a thread.
    /*package*/ static void runOnMainThreadDebounced(DebouncedRunnable r, long delayMillis) {
        postDebounced(sInstance.mMainHandler, r, delayMillis);
    }

    public static CharSequence toDebugString(Object o) {
        return toDebugString(o, false);
    }

    public static CharSequence toDebugString(Object o, boolean isSensitive) {
        if (isSensitive && !LOG_POTENTIALLY_SENSITIVE_INFO) {
            // we could potentially have type-specific partial dumping here
            return privStr("");
        }

        if (o instanceof byte[]) {
            return IccUtils.bytesToHexString((byte[])o);
        } else if (o instanceof IccIoResult) {
            IccIoResult iccIoResult = (IccIoResult)o;
            return iccIoResult.toString()+" "+IccUtils.bytesToHexString(iccIoResult.payload);
        } else if (o instanceof Object[]) {
            return "{"+TextUtils.join(", ", (Object[])o)+"}";
        } else if (o instanceof int[]) {
            Integer[] sa = new Integer[((int[])o).length];
            int i = 0;
            for (int j : (int[]) o) {
                sa[i++] = j;
            }
            return toDebugString(sa);
        } else {
            return String.valueOf(o);
        }
    }

    /*package*/ static String privStr(Object o) {
        //noinspection ConstantConditions
        return LOG_POTENTIALLY_SENSITIVE_INFO ? String.valueOf(o) : "XXXXX";
    }

    /*package*/ static Throwable privExc(Throwable t) {
        // TODO find a way to pass back the safe parts instead of null?
        //noinspection ConstantConditions
        return LOG_POTENTIALLY_SENSITIVE_INFO ? t : null;
    }

    private static void runWithNetworkPermittedOnMainThread(Runnable r) {
        StrictMode.ThreadPolicy standardPolicy = StrictMode.getThreadPolicy();
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder(standardPolicy)
                .permitNetwork()
                .build());

        try {
            r.run();
        } finally {
            StrictMode.setThreadPolicy(standardPolicy);
        }
    }

    /*
     * Works similar to Android's RegistrantList.
     */
    /*package*/ interface RegistrantList {
        void notifyResult(Object result);
    }

}

// mostly a tag type to remind me use this correctly (only construct one for each purpose)
/*package*/ abstract class DebouncedRunnable implements Runnable {}

// does not need to be available at true runtime, just when BuildRilWrapper runs, but
// I'm not sure that can be done without spelunking into classfiles
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
/*package*/ @interface OkOnMainThread {
}
