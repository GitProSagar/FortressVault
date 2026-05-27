package vault.domain;

public sealed interface CryptoResult permits CryptoResult.Success, CryptoResult.Failure {
    record Success(byte[] data) implements CryptoResult {
        // ZERO-TRUST INVARIANT: Explicitly defensive copy the byte array
        // to shield internal data from unexpected background modifications.
        public Success {
            data = data.clone();
        }

        // Custom getter override to enforce strict isolation boundaries
        @Override
        public byte[] data() {
            return data.clone();
        }
    }

    // 2. Represents an expected or unexpected failure boundary condition
    record Failure(String errorMessage , Throwable rootCause) implements CryptoResult {}
}
