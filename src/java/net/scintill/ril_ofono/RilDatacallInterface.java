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
import android.net.KeepalivePacketData;
import android.net.LinkProperties;

interface RilDatacallInterface {

    Object getDataCallList();

    Object getDataRegistrationState();

    Object setupDataCall(int accessNetworkType, DataProfile dataProfile, boolean isRoaming,
                       boolean allowRoaming, int reason, LinkProperties linkProperties);

    Object deactivateDataCall(int cid, int reason);

    Object setInitialAttachApn(DataProfile dataProfile, boolean isRoaming);

    Object setDataAllowed(boolean allowed);

    Object stopNattKeepalive(int sessionHandle);

    Object startNattKeepalive(int contextId, KeepalivePacketData packetData, int intervalMillis);

}
