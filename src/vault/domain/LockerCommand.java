package vault.domain;

/**
 * SEALED : Defines a restricted boundary; only allowed implementations can compile . <br>
 * PERMITS : Explicitly lists the ONLY classes authorized to implement this interface . <br>
 * RECORD : A final, immutable data structure; auto-generates constructor, getters, equals, and hashCode .
 */

public sealed interface LockerCommand permits
        LockerCommand.StorePassword,
        LockerCommand.RetrievePassword,
        LockerCommand.EncryptFile,
        LockerCommand.DecryptFile {

    public static record StorePassword(
            String serviceName,
            String username,
            byte[] plainPassword
    ) implements LockerCommand {

        // Compact Constructor - Defensive copy on input
        public StorePassword {
            if (plainPassword == null) {
                throw new IllegalArgumentException("Payload cannot be null");
            }
            plainPassword = plainPassword.clone(); // Isolate the reference instantly
        }

        // Accessor Override - Defensive copy on output
        @Override
        public byte[] plainPassword() {
            return this.plainPassword.clone();
        }
    }

    record RetrievePassword(String serviceName) implements LockerCommand {}

    record EncryptFile(String sourcePath, String targetPath) implements LockerCommand {}

    record DecryptFile(String sourcePath, String targetPath) implements LockerCommand {}
}
