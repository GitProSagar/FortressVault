package vault.service;

import vault.domain.CryptoResult;
import vault.domain.LockerCommand;
import vault.repository.VaultStorage;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

public final class VaultService {

    private final VaultStorage vaultStorage;

    public VaultService(VaultStorage vaultStorage) {
        this.vaultStorage = vaultStorage;
    }

    public void executionCommand(LockerCommand command, SecretKey deriveKey) throws IOException {

        switch (command) {

            case LockerCommand.StorePassword sp -> {
                // 1. Obtain our defensively isolated array copy
                byte[] rawPasswordBytes = sp.plainPassword();

                try {
                    // 2. Perform AES-GCM encryption math
                    CryptoResult result = CryptoEngine.encrypt(rawPasswordBytes, deriveKey);

                    if (result instanceof CryptoResult.Success success) {
                        vaultStorage.saveEncryptedPayload(sp.serviceName(), success.data());
                        System.out.println("[VAULT SUCCESS] Initial credential safely written to disk.");
                    } else if (result instanceof CryptoResult.Failure(String errorMessage, Throwable rootCause)) {
                        throw new RuntimeException("Encryption Defect: " + errorMessage, rootCause);
                    }
                } finally {
                    // 3. ZERO-OUT memory inside the finally block to guarantee cleanup
                    java.util.Arrays.fill(rawPasswordBytes, (byte) 0);
                }
            }

            case  LockerCommand.RetrievePassword rp -> {
                Optional<byte[]> encryptedData = vaultStorage.findEncryptedPayload(rp.serviceName());

                if (encryptedData.isPresent()){
                    CryptoResult result = CryptoEngine.decrypt(encryptedData.get(), deriveKey);

                    if(result instanceof CryptoResult.Success success){
                        String decryptedPassword = new String(success.data(), StandardCharsets.UTF_8);
                        System.out.println("[VAULT SUCCESS] Retrieved Password for " + rp.serviceName() + ": " + decryptedPassword);
                    }else if (result instanceof CryptoResult.Failure failure) {
                        System.err.println("[VAULT ERROR] Decryption failed: " + failure.errorMessage());
                    }
                }else {
                    System.err.println("[VAULT ERROR] No credential payload found for: " + rp.serviceName());
                }
            }

            case LockerCommand.EncryptFile ef -> {
                // Bulk logic mapping for streaming file paths can be injected here
                System.out.println("[VAULT FILE-SYSTEM] Initializing stream encryption for target: " + ef.sourcePath());
            }

            case LockerCommand.DecryptFile df -> {
                // Bulk logic mapping for streaming file paths can be injected here
                System.out.println("[VAULT FILE-SYSTEM] Initializing stream decryption for target: " + df.sourcePath());
            }
        }
    }
}
