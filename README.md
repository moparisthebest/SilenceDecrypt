SilenceDecrypt
--------------

Silence is a great Android SMS client, but I recently found out the hard way the plaintext backup does not include MMS, and worse, even if you get the sqlite database, all messages are encrypted.  So this uses SecureSMS-Preferences.xml, messages.db, and your passphrase, to decrypt all messages in the database.

Usage
-----
```sh
# build like so:
mvn package

# now, with an encrypted Silence backup folder in the current working directory named 'SilenceExport'

# to export texts and attachments to plaintext files, run (args optional):
java -jar target/SilenceDecrypt.jar [your-phone-number] [yourpassphrase]

# to decrypt messages.db and mms files only, run (args optional):
java -cp target/SilenceDecrypt.jar org.smssecure.smssecure.crypto.SilenceDecrypt [yourpassphrase]
```

License
-------
AGPLv3
