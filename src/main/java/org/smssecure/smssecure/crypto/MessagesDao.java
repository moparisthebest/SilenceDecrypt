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
import com.moparisthebest.jdbc.util.ResultSetIterable;

@JdbcMapper.Mapper
public interface MessagesDao extends JdbcMapper {

    class Message {
        long id;
        String body;

        @Override
        public String toString() {
            return "Message{" +
                    "id=" + id +
                    ", body='" + body + '\'' +
                    '}';
        }
    }

    @SQL("SELECT _id, body FROM sms WHERE body IS NOT NULL")
    ResultSetIterable<Message> getSms();

    @SQL("UPDATE sms SET body = {body} WHERE _id = {id}")
    boolean updateSms(long id, String body);

    @SQL("SELECT _id, body FROM mms WHERE body IS NOT NULL")
    ResultSetIterable<Message> getMms();

    @SQL("UPDATE mms SET body = {body} WHERE _id = {id}")
    boolean updateMms(long id, String body);

    @SQL("SELECT _id, snippet AS body FROM thread WHERE snippet IS NOT NULL")
    ResultSetIterable<Message> getThread();

    @SQL("UPDATE thread SET snippet = {body} WHERE _id = {id}")
    boolean updateThread(long id, String body);
}
