import vault.domain.LockerCommand;
import vault.repository.VaultStorage;
import vault.service.CryptoEngine;
import vault.service.VaultService;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class Main {

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println("    INITIALIZING FORTRESS-VAULT CRYPTO SYSTEM    ");
        System.out.println("=================================================");

        char[] masterPassword = "MasterCloudAdminKey#2026!".toCharArray();
        byte[] salt = "FixedProductionSaltVectorBytes".getBytes(StandardCharsets.UTF_8);
        ExecutorService threadPool = null;

        try {
            System.out.println("[BOOTSTRAP] Deriving Secret Key via PBKDF2-HmacSHA256...");
            SecretKey derivedKey = CryptoEngine.deriveKey(masterPassword, salt);
            System.out.println("[BOOTSTRAP] Cryptographic key successfully materialized.");

            // Clear sensitive plaintext master password from heap RAM instantly
            Arrays.fill(masterPassword, '0');

            Path databasePath = Paths.get("./fortress_vault_data");
            VaultStorage storage = new VaultStorage(databasePath);
            VaultService vaultService = new VaultService(storage);
            System.out.println("[BOOTSTRAP] Storage Layer initialized at: " + databasePath.toAbsolutePath());

            // --- FIXED INGESTION STEP ---
            System.out.println("[SIMULATION] Performing Synchronous Base Write...");
            byte[] secretBytes = "GitHubPersonalToken_XYZ987".getBytes(StandardCharsets.UTF_8);

            LockerCommand storeCmd = new LockerCommand.StorePassword(
                    "GitHub-API",
                    "admin_user",
                    secretBytes
            );

            // Execute synchronously to ensure disk settlement before read simulation starts
            vaultService.executionCommand(storeCmd, derivedKey);

            // Clean local reference buffer safely now that data is isolated inside the vault
            Arrays.fill(secretBytes, (byte) 0);

            // --- CONCURRENT TRAFFIC STAMPEDE ---
            int totalReadThreads = 10;
            CountDownLatch entryBarrier = new CountDownLatch(1);
            CountDownLatch completionLatch = new CountDownLatch(totalReadThreads);

            threadPool = Executors.newFixedThreadPool(totalReadThreads);
            System.out.println("[SIMULATION] Spawning " + totalReadThreads + " concurrent read paths...");

            for (int i = 0; i < totalReadThreads; i++) {
                threadPool.submit(() -> {
                    try {
                        entryBarrier.await(); // Park all threads on the starting line

                        LockerCommand readCmd = new LockerCommand.RetrievePassword("GitHub-API");
                        vaultService.executionCommand(readCmd, derivedKey);
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        completionLatch.countDown();
                    }
                });
            }

            // DROP THE FLOODGATES: 10 parallel threads hit the ReadLock simultaneously
            System.out.println("[SIMULATION] Blasting concurrent traffic barriers now...");
            long startTime = System.currentTimeMillis();
            entryBarrier.countDown();

            completionLatch.await();
            long endTime = System.currentTimeMillis();

            System.out.println("=================================================");
            System.out.println("   SIMULATION COMPLETE IN " + (endTime - startTime) + " MS");
            System.out.println("=================================================");

        } catch (Exception e) {
            System.err.println("[CRITICAL FAILURE]: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (threadPool != null) {
                threadPool.shutdown();
            }
        }
    }
}