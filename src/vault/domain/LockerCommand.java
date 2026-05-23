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

    record StorePassword(
            String serviceName,
            String username,
            byte[] plainPassword
    ) implements LockerCommand {
        public StorePassword {
            plainPassword = plainPassword.clone();
        }
    }

    record RetrievePassword(String serviceName) implements LockerCommand {}

    record EncryptFile(String sourcePath, String targetPath) implements LockerCommand {}

    record DecryptFile(String sourcePath, String targetPath) implements LockerCommand {}
}
