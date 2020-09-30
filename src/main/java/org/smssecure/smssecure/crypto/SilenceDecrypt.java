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

import com.moparisthebest.jdbc.codegen.JdbcMapperFactory;
import com.moparisthebest.jdbc.util.ResultSetIterable;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.smssecure.smssecure.crypto.MasterSecretUtil.UNENCRYPTED_PASSPHRASE;

public class SilenceDecrypt {
    public static void main(String[] args) throws Exception {
        var passphrase = UNENCRYPTED_PASSPHRASE;
        if (args.length > 0) {
            passphrase = args[0];
        }
        final var silenceExportDir = new File("SilenceExport");
        final var appPartsDir = new File(silenceExportDir, "app_parts");
        final var masterSecret = MasterSecretUtil.getMasterSecret(new File(silenceExportDir, "shared_prefs/SecureSMS-Preferences.xml"), passphrase);
        final var messagesDbOrigPath = new File(silenceExportDir, "databases/messages.db").toPath();
        final var messagesDbFilePath = "messages.db";
        final var outDir = new File("app_parts");
        outDir.mkdirs();

        // copy original database here to modify
        Files.copy(messagesDbOrigPath, Path.of(messagesDbFilePath));

        final var masterCipher = new MasterCipher(masterSecret);

        final var mmsFiles = appPartsDir.listFiles((f, n) -> n.toLowerCase().endsWith(".mms"));
        if (mmsFiles != null) {
            for (final var file : mmsFiles) {
                final var encryptedBytes = Files.readAllBytes(file.toPath());
                //System.out.println(part + Arrays.toString(encryptedBytes));
                final var decryptedBytes = masterCipher.decryptBytes(encryptedBytes);
                final var attachmentFile = new File(outDir, file.getName());
                Files.write(attachmentFile.toPath(), decryptedBytes);
            }
        }

        try (var conn = DriverManager.getConnection("jdbc:sqlite:" + messagesDbFilePath);
             var dao = JdbcMapperFactory.create(MessagesDao.class, conn)) {
            decrypt(masterCipher, dao::getSms, msg -> dao.updateSms(msg.id, msg.body));
            decrypt(masterCipher, dao::getMms, msg -> dao.updateMms(msg.id, msg.body));
            decrypt(masterCipher, dao::getThread, msg -> dao.updateThread(msg.id, msg.body));
        }
    }

    private static void decrypt(final MasterCipher masterCipher, final Supplier<ResultSetIterable<MessagesDao.Message>> messages, final Consumer<MessagesDao.Message> update) {
        try (var msgs = messages.get()) {
            for (final var msg : msgs) {
                var bodyChanged = false;
                try {
                    msg.body = masterCipher.decryptBody(msg.body);
                    bodyChanged = true;
                } catch (Exception e) {
                    // ignore, maybe already decrypted, regardless we can't do anything
                }
                if (bodyChanged) {
                    update.accept(msg);
                }
            }
        }
    }
}
