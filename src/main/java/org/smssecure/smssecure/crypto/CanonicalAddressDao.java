/**
 * Copyright (C) 2020 Travis Burtrum (moparisthebest)
 * <p>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * <p>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.smssecure.smssecure.crypto;

import com.moparisthebest.jdbc.codegen.JdbcMapper;
import com.moparisthebest.jdbc.codegen.JdbcMapperFactory;

import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Map;

/*
.schema:
CREATE TABLE android_metadata (locale TEXT);
CREATE TABLE canonical_addresses (_id integer PRIMARY KEY, address TEXT NOT NULL);
*/

@JdbcMapper.Mapper
public interface CanonicalAddressDao extends JdbcMapper {

    @SQL("SELECT _id, address FROM canonical_addresses")
    Map<Long, String> getCanonicalAddresses();

    static Map<Long, String> getCanonicalAddresses(String dbUrl) throws SQLException {
        try (var conn = DriverManager.getConnection(dbUrl);
             var dao = JdbcMapperFactory.create(CanonicalAddressDao.class, conn)) {
            return dao.getCanonicalAddresses();
        }
    }

}
