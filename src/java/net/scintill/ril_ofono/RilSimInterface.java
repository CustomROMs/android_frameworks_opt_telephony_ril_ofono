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

interface RilSimInterface {

    Object getIccCardStatus();

    Object getIMSI();

    Object getIMSIForApp(String aid);

    Object iccIOForApp(int command, int fileid, String path, int p1, int p2, int p3, String data, String pin2, String aid);

    Object iccIO(int command, int fileid, String path, int p1, int p2, int p3, String data, String pin2);

}
