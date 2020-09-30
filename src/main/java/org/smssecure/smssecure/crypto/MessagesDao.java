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
import org.smssecure.smssecure.database.MmsSmsColumns;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/*
.schema:
CREATE TABLE android_metadata (locale TEXT);
CREATE TABLE sms (_id integer PRIMARY KEY, thread_id INTEGER, address TEXT, address_device_id INTEGER DEFAULT 1, person INTEGER, date INTEGER, date_sent INTEGER, protocol INTEGER, read INTEGER DEFAULT 0, status INTEGER DEFAULT -1,type INTEGER, reply_path_present INTEGER, date_delivery_received INTEGER DEFAULT 0,subject TEXT, body TEXT, mismatched_identities TEXT DEFAULT NULL, service_center TEXT, subscription_id INTEGER DEFAULT -1, notified DEFAULT 0);
CREATE TABLE mms (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, date_received INTEGER, msg_box INTEGER, read INTEGER DEFAULT 0, m_id TEXT, sub TEXT, sub_cs INTEGER, body TEXT, part_count INTEGER, ct_t TEXT, ct_l TEXT, address TEXT, address_device_id INTEGER, exp INTEGER, m_cls TEXT, m_type INTEGER, v INTEGER, m_size INTEGER, pri INTEGER, rr INTEGER, rpt_a INTEGER, resp_st INTEGER, st INTEGER, tr_id TEXT, retr_st INTEGER, retr_txt TEXT, retr_txt_cs INTEGER, read_status INTEGER, ct_cls INTEGER, resp_txt TEXT, d_tm INTEGER, date_delivery_received INTEGER DEFAULT 0, mismatched_identities TEXT DEFAULT NULL, network_failures TEXT DEFAULT NULL,d_rpt INTEGER, subscription_id INTEGER DEFAULT -1, notified INTEGER DEFAULT 0);
CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER, seq INTEGER DEFAULT 0, ct TEXT, name TEXT, chset INTEGER, cd TEXT, fn TEXT, cid TEXT, cl TEXT, ctt_s INTEGER, ctt_t TEXT, encrypted INTEGER, pending_push INTEGER, _data TEXT, data_size INTEGER, thumbnail TEXT, aspect_ratio REAL, unique_id INTEGER NOT NULL);
CREATE TABLE thread (_id INTEGER PRIMARY KEY, date INTEGER DEFAULT 0, message_count INTEGER DEFAULT 0, recipient_ids TEXT, snippet TEXT, snippet_cs INTEGER DEFAULT 0, read INTEGER DEFAULT 1, type INTEGER DEFAULT 0, error INTEGER DEFAULT 0, snippet_type INTEGER DEFAULT 0, snippet_uri TEXT DEFAULT NULL, archived INTEGER DEFAULT 0, status INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0);
CREATE TABLE mms_addresses (_id INTEGER PRIMARY KEY, mms_id INTEGER, type INTEGER, address TEXT, address_charset INTEGER);
CREATE TABLE identities (_id INTEGER PRIMARY KEY, recipient INTEGER UNIQUE, key TEXT, mac TEXT);
CREATE TABLE drafts (_id INTEGER PRIMARY KEY, thread_id INTEGER, type TEXT, value TEXT);
CREATE TABLE recipient_preferences (_id INTEGER PRIMARY KEY, recipient_ids TEXT UNIQUE, block INTEGER DEFAULT 0,notification TEXT DEFAULT NULL, vibrate INTEGER DEFAULT 0, mute_until INTEGER DEFAULT 0, color TEXT DEFAULT NULL, default_subscription_id INTEGER DEFAULT -1);
*/

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

    class ThreadMessage {
        long threadId, msgId;
        boolean sentNotReceived;

        int partCount;

        String recipientIds, body;

        Instant date;

        public void setType(long type) {
            this.sentNotReceived = MmsSmsColumns.Types.isOutgoingMessageType(type);
        }

        public void setDate(long date) {
            this.date = Instant.ofEpochMilli(date);
        }

        public void setBody(String body) {
            this.body = body == null ? "" : body;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ThreadMessage that = (ThreadMessage) o;
            return sentNotReceived == that.sentNotReceived &&
                    partCount == that.partCount &&
                    Objects.equals(recipientIds, that.recipientIds) &&
                    Objects.equals(body, that.body) &&
                    Objects.equals(date, that.date);
        }

        @Override
        public int hashCode() {
            return Objects.hash(sentNotReceived, partCount, recipientIds, body, date);
        }

        @Override
        public String toString() {
            return "ThreadMessage{" +
                    "threadId=" + threadId +
                    ", msgId=" + msgId +
                    ", date=" + date +
                    ", sentNotReceived=" + sentNotReceived +
                    ", partCount=" + partCount +
                    ", recipientIds='" + recipientIds + '\'' +
                    ", body='" + body + '\'' +
                    '}';
        }
    }

    @SQL("SELECT t._id thread_id, t.recipient_ids, msg._id msg_id, msg.date, msg.body, msg.type, msg.part_count\n" +
            "FROM thread t\n" +
            "JOIN (\n" +
            "    SELECT _id, thread_id, date, body, type, 0 AS part_count FROM sms\n" +
            "    UNION\n" +
            "    SELECT msg._id, msg.thread_id, msg.date, msg.body, addr.type, msg.part_count FROM mms msg\n" +
            "    JOIN mms_addresses addr ON msg._id = addr.mms_id AND ((addr.type = 137 AND msg.subscription_id = 1) OR (addr.type = 151 AND msg.subscription_id = -1))\n" +
            ") msg ON msg.thread_id = t._id\n" +
            "WHERE t.recipient_ids NOT LIKE '% %'\n" +
            "ORDER BY t._id, msg.date")
    ResultSetIterable<ThreadMessage> getAllSingleRecipientMessages();

    @SQL("SELECT t._id thread_id, addr.address recipient_ids, msg._id msg_id, msg.date, msg.body, addr.type, msg.part_count\n" +
            "FROM thread t\n" +
            "JOIN mms msg ON msg.thread_id = t._id\n" +
            "JOIN mms_addresses addr ON msg._id = addr.mms_id\n" +
            "WHERE t.recipient_ids LIKE '% %' AND ((addr.type = 137 AND msg.subscription_id = 1) OR (addr.type = 151 AND msg.subscription_id = -1))\n" +
            "ORDER BY t._id, msg.date")
    ResultSetIterable<ThreadMessage> getAllGroupMessages();

    class Part {
        String ct, data;

        public String getExtension() {
            return switch (ct) {
                case "image/png" -> ".png";
                case "image/jpeg" -> ".jpg";
                case "image/gif" -> ".gif";
                case "image/bmp" -> ".bmp";
                case "video/3gpp" -> ".3gp";
                case "video/mp4" -> ".mp4";
                case "audio/mp4" -> ".mp4";
                default -> throw new RuntimeException("extension unknown for content type: " + ct);
            };
        }

        public String getDataFilename() {
            return data.replaceAll(".*/", "");
        }

        @Override
        public String toString() {
            return "Part{" +
                    "ct='" + ct + '\'' +
                    ", data='" + data + '\'' +
                    '}';
        }
    }

    @SQL("SELECT ct, _data FROM part WHERE mid = {msgId} ORDER BY seq")
    List<Part> getMmsParts(long msgId);
}
