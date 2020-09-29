SilenceDecrypt
--------------

Silence is a great Android SMS client, but I recently found out the hard way the plaintext backup does not include MMS, and worse, even if you get the sqlite database, all messages are encrypted.  So this uses SecureSMS-Preferences.xml, messages.db, and your passphrase, to decrypt all messages in the database.

It will also extract plaintext backups.