package vault.repository;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public final class VaultStorage {

    private final Map<String, byte[]> memoryCache = new HashMap<>();

    private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock(true);
    private final Lock readLock = rwLock.readLock();
    private final Lock writeLock = rwLock.writeLock();

    private final Path storageDirectory;


    public VaultStorage(Path storageDirectory) throws IOException {
        this.storageDirectory = storageDirectory;
        if(!Files.exists(storageDirectory)){
            Files.createDirectories(storageDirectory);
        }
    }

    public Optional<byte[]> findEncryptedPayload(String serviceName) {
        readLock.lock();
        try {
            byte[] cachedData = memoryCache.get(serviceName);
            if (cachedData == null){
                return Optional.empty();
            }

            return Optional.of(cachedData.clone());
        }finally {
            readLock.unlock();
        }
    }

    public void saveEncryptedPayload(String serviceName , byte[] encryptedPayload) throws IOException{
        writeLock.lock();
        try {
            memoryCache.put(serviceName, encryptedPayload.clone());

            Path targetFile = storageDirectory.resolve(serviceName + ".vault");
            Files.write(targetFile, encryptedPayload,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
        } finally {
            writeLock.unlock();
        }
    }
}
