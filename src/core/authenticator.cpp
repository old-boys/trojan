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

#include "authenticator.h"
#include <cstdlib>
#include <stdexcept>
using namespace std;

#ifdef ENABLE_MYSQL

Authenticator::Authenticator(const Config &config) {
    mysql_init(&con);
    Log::log_with_date_time("connecting to MySQL server " + config.mysql.server_addr + ':' + to_string(config.mysql.server_port), Log::INFO);
    if (config.mysql.cafile != "") {
        mysql_ssl_set(&con, NULL, NULL, config.mysql.cafile.c_str(), NULL, NULL);
    }
    if (mysql_real_connect(&con, config.mysql.server_addr.c_str(),
                                 config.mysql.username.c_str(),
                                 config.mysql.password.c_str(),
                                 config.mysql.database.c_str(),
                                 config.mysql.server_port, NULL, 0) == NULL) {
        throw runtime_error(mysql_error(&con));
    }
    bool reconnect = 1;
    mysql_options(&con, MYSQL_OPT_RECONNECT, &reconnect);
    Log::log_with_date_time("connected to MySQL server", Log::INFO);
}

bool Authenticator::auth(const string &password, uint64_t &user_id, const Config &config, SStatus &sstatus) {
    if (!is_valid_password(password)) {
        return false;
    }

    if (sstatus.user_access.find(password) != sstatus.user_access.end()) {
        user_id = sstatus.user_access[password].userid;
        //Log::log_with_date_time(password + " @ " + to_string(sstatus.user_access[password].userid) + " cache access ok !!!! " + to_string(sstatus.user_access[password].access), Log::FATAL);
        return sstatus.user_access[password].access;
    }

    if (mysql_query(&con, ("SELECT transfer_enable, d + u, class, id FROM user WHERE password = '" + password + '\'').c_str())) {
        Log::log_with_date_time(mysql_error(&con), Log::ERROR);
        return false;
    }
    MYSQL_RES *res = mysql_store_result(&con);
    if (res == NULL) {
        Log::log_with_date_time(mysql_error(&con), Log::ERROR);
        return false;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row == NULL) {
        mysql_free_result(res);
        return false;
    }
    uint64_t transfer_enable = strtoull(row[0], NULL, 10);
    uint64_t bandwidth_used = strtoull(row[1], NULL, 10);
    uint64_t user_class = strtoull(row[2], NULL, 10);
    user_id =  strtoull(row[3], NULL, 10);
    mysql_free_result(res);

    uint64_t bandwidth_real_used = bandwidth_used;

    if (user_class < config.node_class) {
        sstatus.user_access.insert(pair<string, SStatus::Access>(password, {user_id, false}));
        Log::log_with_date_time(password + " user class smaller than node", Log::WARN);
        return false;
    }

   if (sstatus.user_transfer.find(user_id) != sstatus.user_transfer.end()) {
		bandwidth_real_used += (sstatus.user_transfer[user_id].upload + sstatus.user_transfer[user_id].download);
   }
   if (bandwidth_real_used >= transfer_enable) {
        sstatus.user_access.insert(pair<string, SStatus::Access>(password, {user_id, false}));
        Log::log_with_date_time(password + " ran out of bandwidth", Log::WARN);
        return false;
    }

    sstatus.user_access.insert(pair<string, SStatus::Access>(password, {user_id, true}));

   // Log::log_with_date_time(password + " @" + to_string(sstatus.user_access[password].userid) + " access ok @@@@@ " + to_string(sstatus.user_access[password].access), Log::FATAL);
    //TODO: add disconnect ip here

    return true;
}

bool Authenticator::is_valid_password(const string &password) {
    if (password.size() != PASSWORD_LENGTH) {
        return false;
    }
    for (size_t i = 0; i < PASSWORD_LENGTH; ++i) {
        if (!((password[i] >= '0' && password[i] <= '9') || (password[i] >= 'a' && password[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

Authenticator::~Authenticator() {
    mysql_close(&con);
}

#else // ENABLE_MYSQL

Authenticator::Authenticator(const Config&) {}
bool Authenticator::auth(const string&, uint64_t &, uint64_t &, uint64_t &, const Config&, SStatus&) { return true; }
bool Authenticator::is_valid_password(const string&) { return true; }
Authenticator::~Authenticator() {}

#endif // ENABLE_MYSQL
