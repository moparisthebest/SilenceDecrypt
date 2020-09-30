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

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.sql.DriverManager;
import java.time.ZoneId;
import java.time.format.DateTimeFormatterBuilder;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.smssecure.smssecure.crypto.MasterSecretUtil.UNENCRYPTED_PASSPHRASE;

public class SilenceExport {

    public static void main(String[] args) throws Exception {
        var passphrase = UNENCRYPTED_PASSPHRASE;
        var myNumber = "Me";
        if (args.length > 0) {
            myNumber = formatPhoneNumber(args[0]);
        }
        if (args.length > 1) {
            passphrase = args[1];
        }
        final var silenceExportDir = new File("SilenceExport");
        final var appPartsDir = new File(silenceExportDir, "app_parts");
        final var masterSecret = MasterSecretUtil.getMasterSecret(new File(silenceExportDir, "shared_prefs/SecureSMS-Preferences.xml"), passphrase);
        final var messagesDbFilePath = new File(silenceExportDir, "databases/messages.db").getAbsolutePath();
        final var canonicalAddressDbFilePath = new File(silenceExportDir, "databases/canonical_address.db").getAbsolutePath();
        final var dateFormatter = new DateTimeFormatterBuilder().parseCaseInsensitive().appendPattern("dd-MMM-uuuu hh:mm:ss a z").toFormatter(Locale.US).withZone(ZoneId.of("America/New_York"));
        final var outDir = new File("out");
        outDir.mkdirs();

        final var masterCipher = new MasterCipher(masterSecret);

        try (var conn = DriverManager.getConnection("jdbc:sqlite:" + messagesDbFilePath);
             var dao = JdbcMapperFactory.create(MessagesDao.class, conn)) {

            int attachmentCount = -1; // start at 0
            final var attachedFiles = new ArrayList<String>();

            // export SMS
            {
                final var canonicalAddresses = CanonicalAddressDao.getCanonicalAddresses("jdbc:sqlite:" + canonicalAddressDbFilePath)
                        .entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> formatPhoneNumber(e.getValue())));

                // these we update per-thread
                String contact = null;
                long lastThreadId = Long.MIN_VALUE;
                MessagesDao.ThreadMessage lastMessage = null;
                PrintStream ps = null;
                File outputFile = null;
                FileOutputStream fos = null;
                // end per-thread state

                try (var smss = dao.getAllSingleRecipientMessages()) {
                    for (final var sms : smss) {
                        if (Objects.equals(lastMessage, sms)) {
                            continue; // sometimes messages are duplicated, don't print these
                        }
                        lastMessage = sms;
                        sms.body = masterCipher.tryDecryptBody(sms.body);
                        //System.out.println(sms);
                        if (lastThreadId != sms.threadId) {
                            // new file
                            lastThreadId = sms.threadId;
                            contact = canonicalAddresses.get(Long.parseLong(sms.recipientIds)); // query ensures this is a single number
                            if (outputFile != null) {
                                ps.close();
                                fos.close();
                                outputFile.setLastModified(lastMessage.date.toEpochMilli());
                            }
                            outputFile = new File(outDir, contact + ".txt");
                            fos = new FileOutputStream(outputFile);
                            ps = new PrintStream(fos);
                        }
                        if (sms.partCount > 0) {
                            attachedFiles.clear();
                            for (final var part : dao.getMmsParts(sms.msgId)) {
                                final var encryptedBytes = Files.readAllBytes(new File(appPartsDir, part.getDataFilename()).toPath());
                                //System.out.println(part + Arrays.toString(encryptedBytes));
                                final var decryptedBytes = masterCipher.decryptBytes(encryptedBytes);
                                final String filename = "attachment" + ++attachmentCount + part.getExtension();
                                attachedFiles.add(filename);
                                final var attachmentFile = new File(outDir, filename);
                                Files.write(attachmentFile.toPath(), decryptedBytes);
                                attachmentFile.setLastModified(sms.date.toEpochMilli());
                            }
                            ps.printf("(%s) [%s] [attached files: %s]: %s%n", dateFormatter.format(sms.date), sms.sentNotReceived ? myNumber : contact, String.join(",", attachedFiles), sms.body);
                        } else {
                            ps.printf("(%s) [%s]: %s%n", dateFormatter.format(sms.date), sms.sentNotReceived ? myNumber : contact, sms.body);
                        }
                    }
                    if (ps != null && fos != null) {
                        ps.close();
                        fos.close();
                        outputFile.setLastModified(lastMessage.date.toEpochMilli());
                    }
                }
            }

            // export MMS
            {
                final var uniqueContacts = new HashSet<String>();

                // these we update per-thread
                long lastThreadId = Long.MIN_VALUE;
                MessagesDao.ThreadMessage lastMessage = null;
                PrintStream ps = null;
                File outputFile = null;
                FileOutputStream fos = null;
                // end per-thread state

                try (var smss = dao.getAllGroupMessages()) {
                    for (final var sms : smss) {
                        final var contact = sms.recipientIds = sms.sentNotReceived ? myNumber : formatPhoneNumber(sms.recipientIds);
                        if (Objects.equals(lastMessage, sms)) {
                            continue; // sometimes messages are duplicated, don't print these
                        }
                        lastMessage = sms;
                        sms.body = masterCipher.tryDecryptBody(sms.body);
                        uniqueContacts.add(contact);
                        //System.out.println(sms);
                        if (lastThreadId != sms.threadId) {
                            // new file
                            lastThreadId = sms.threadId;
                            if (outputFile != null) {
                                ps.close();
                                fos.close();
                                outputFile.setLastModified(lastMessage.date.toEpochMilli());
                                outputFile.renameTo(new File(outDir, uniqueContacts.stream().sorted().collect(Collectors.joining(",")) + ".txt"));
                                uniqueContacts.clear();
                            }
                            outputFile = new File(outDir, "tmp_mms_out.txt");
                            fos = new FileOutputStream(outputFile);
                            ps = new PrintStream(fos);
                        }
                        if (sms.partCount > 0) {
                            attachedFiles.clear();
                            for (final var part : dao.getMmsParts(sms.msgId)) {
                                final var encryptedBytes = Files.readAllBytes(new File(appPartsDir, part.getDataFilename()).toPath());
                                //System.out.println(part + Arrays.toString(encryptedBytes));
                                final var decryptedBytes = masterCipher.decryptBytes(encryptedBytes);
                                final String filename = "attachment" + ++attachmentCount + part.getExtension();
                                attachedFiles.add(filename);
                                final var attachmentFile = new File(outDir, filename);
                                Files.write(attachmentFile.toPath(), decryptedBytes);
                                attachmentFile.setLastModified(sms.date.toEpochMilli());
                            }
                            ps.printf("(%s) [%s] [attached files: %s]: %s%n", dateFormatter.format(sms.date), contact, String.join(",", attachedFiles), sms.body);
                        } else {
                            ps.printf("(%s) [%s]: %s%n", dateFormatter.format(sms.date), contact, sms.body);
                        }
                    }
                    if (ps != null && fos != null) {
                        ps.close();
                        fos.close();
                        outputFile.setLastModified(lastMessage.date.toEpochMilli());
                        outputFile.renameTo(new File(outDir, uniqueContacts.stream().sorted().collect(Collectors.joining(",")) + ".txt"));
                    }
                }
            }
        }
    }

    private static final Pattern nonNumeric = Pattern.compile("[^0-9]");

    static String formatPhoneNumber(final String orig) {
        String onlyNumeric = nonNumeric.matcher(orig).replaceAll("");
        switch (onlyNumeric.length()) {
            case 11:
                if (onlyNumeric.charAt(0) == '1') {
                    // we will just strip this off, and let it fall into 10 slot
                    onlyNumeric = onlyNumeric.substring(1);
                } else {
                    return orig;
                }
            case 10:
                return onlyNumeric.substring(0, 3) + '-' + onlyNumeric.substring(3, 6) + '-' + onlyNumeric.substring(6, 10);
            default:
                return orig;
        }
    }
}
