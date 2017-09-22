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

import android.telephony.Rlog;

import org.freedesktop.dbus.Variant;
import org.ofono.Modem;

import java.util.HashMap;
import java.util.Map;

import static com.android.internal.telephony.CommandsInterface.RadioState;

/*package*/ class ModemModule extends PropManager implements RilModemInterface {

    private static final String TAG = RilOfono.TAG;

    private Modem mModem;
    private final Map<String, Variant<?>> mModemProps = new HashMap<>();

    /*package*/ ModemModule(Modem modem) {
        mModem = modem;

        mirrorProps(Modem.class, mModem, Modem.PropertyChanged.class, mModemProps);
    }

    @Override
    @OkOnMainThread
    public Object getIMEI() {
        // TODO GSM-specific?
        return new PrivResponseOb(getProp(mModemProps, "Serial", ""));
    }

    @Override
    @OkOnMainThread
    public Object getIMEISV() {
        // TODO GSM-specific?
        return new PrivResponseOb(getProp(mModemProps, "SoftwareVersionNumber", ""));
    }

    @Override
    public Object setRadioPower(final boolean on) {
        Rlog.v(TAG, "setRadioPower("+on+")");

        mModem.SetProperty("Online", new Variant<>(on));
        return null;
    }

    @Override
    @OkOnMainThread
    public Object getBasebandVersion() {
        return getProp(mModemProps, "Revision", "");
    }

    protected void onPropChange(Modem modem, String name, Variant<?> value) {
        if (name.equals("Online")) {
            final boolean online = (Boolean) value.getValue();
            RilOfono.sInstance.setRadioState(online ? RadioState.RADIO_ON : RadioState.RADIO_OFF);
        }
    }

}
