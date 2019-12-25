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

import java.util.List;

import android.telephony.data.DataProfile;
import android.telephony.NetworkScanRequest;
import android.service.carrier.CarrierIdentifier;

interface RilNetworkRegistrationInterface {

    Object getOperator();

    Object getNetworkSelectionMode();

    Object getSignalStrength();

    Object getVoiceRegistrationState();

    Object getVoiceRadioTechnology();

    Object startLceService(int reportIntervalMs, boolean pullMode);

    Object stopLceService();

    Object pullLceData();

    Object setLinkCapacityReportingCriteria(
              final int hysteresisMs, final int hysteresisDlKbps,
              final int hysteresisUlKbps, final int[] thresholdsDlKbps,
              final int[] thresholdsUlKbps, final int ran);

    Object setSignalStrengthReportingCriteria(
              final int hysteresisMs, final int hysteresisDb,
              final int[] thresholdsDbm, final int ran);

    //Object setAllowedCarriers(List<CarrierIdentifier> carriers);

    Object getAllowedCarriers();

    Object sendDeviceState(int stateType, boolean state);

    Object setUnsolResponseFilter(int filter);

    Object startNetworkScan(NetworkScanRequest nsr);

    Object stopNetworkScan();

}
