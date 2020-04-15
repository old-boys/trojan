/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SSTATUS_H_
#define _SSTATUS_H_

#include <cstdint>
#include <string>
#include <map>
#include <set>
#include "log.h"

class SStatus {
public:
    class UTransfer {
    public:
	    uint64_t upload;
        uint64_t download;
    };
    std::set<uint64_t> online_user;
    uint64_t bandwidth;
    std::map<std::string, uint64_t> ipset;
    std::map<uint64_t, UTransfer> user_transfer;   
    void init();
};

#endif // _SSTATUS_H_
