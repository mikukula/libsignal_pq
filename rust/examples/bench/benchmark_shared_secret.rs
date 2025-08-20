use libsignal_protocol::*;
use pswoosh::keys::SwooshKeyPair;
use rand::rng;
use std::time::{Duration, Instant};

/// Comprehensive benchmark comparing Swoosh post-quantum vs Diffie-Hellman shared secret derivation
fn main() -> Result<(), SignalProtocolError> {
    use std::thread;
    
    // Create a thread with larger stack to run the async main
    let handle = thread::Builder::new()
        .stack_size(100 * 1024 * 1024) // 100MB stack for post-quantum operations
        .spawn(|| {
            benchmark_main()
        })
        .unwrap();
    
    handle.join().unwrap()
}

fn benchmark_main() -> Result<(), SignalProtocolError> {
    println!("=== SHARED SECRET DERIVATION BENCHMARK ===");
    println!("Comparing Swoosh Post-Quantum vs Diffie-Hellman (X25519) performance");
    println!("----------------------------------------------------------");
    
    // Initialize random number generator
    let mut csprng = rng();
    
    // Benchmark configuration
    let num_iterations = 1000;  // Number of derivations to benchmark
    let num_keypairs = 100;     // Number of different key pairs to test
    let warmup_iterations = 50; // Warmup runs to stabilize CPU/cache
    
    println!("Configuration:");
    println!("• Total iterations: {}", num_iterations);
    println!("• Different key pairs: {}", num_keypairs);
    println!("• Warmup iterations: {}", warmup_iterations);
    println!("• Thread stack size: Large (for post-quantum operations)");
    println!();
    
    // Storage for benchmark results
    let mut swoosh_times: Vec<Duration> = Vec::with_capacity(num_iterations);
    let mut dh_times: Vec<Duration> = Vec::with_capacity(num_iterations);
    let mut swoosh_key_gen_times: Vec<Duration> = Vec::with_capacity(num_keypairs);
    let mut dh_key_gen_times: Vec<Duration> = Vec::with_capacity(num_keypairs);
    
    // Pre-generate key pairs to avoid including key generation time in derivation benchmarks
    println!("=== PHASE 1: KEY GENERATION BENCHMARKS ===");
    let mut swoosh_keypairs: Vec<(SwooshKeyPair, SwooshKeyPair)> = Vec::with_capacity(num_keypairs);
    let mut dh_keypairs: Vec<(KeyPair, KeyPair)> = Vec::with_capacity(num_keypairs);
    
    for i in 0..num_keypairs {
        if i % 20 == 0 {
            println!("Generating key pair batch {}/{}", i + 1, num_keypairs);
        }
        
        // Benchmark Swoosh key generation
        let start = Instant::now();
        let alice_swoosh = SwooshKeyPair::generate(true);   // Alice is true
        let bob_swoosh = SwooshKeyPair::generate(false);    // Bob is false
        let swoosh_keygen_time = start.elapsed();
        swoosh_key_gen_times.push(swoosh_keygen_time);
        swoosh_keypairs.push((alice_swoosh, bob_swoosh));
        
        // Benchmark Diffie-Hellman key generation
        let start = Instant::now();
        let alice_dh = KeyPair::generate(&mut csprng);
        let bob_dh = KeyPair::generate(&mut csprng);
        let dh_keygen_time = start.elapsed();
        dh_key_gen_times.push(dh_keygen_time);
        dh_keypairs.push((alice_dh, bob_dh));
    }
    
    // Display key generation results
    let (swoosh_kg_mean, swoosh_kg_std, swoosh_kg_min, swoosh_kg_max) = calculate_stats(&swoosh_key_gen_times);
    let (dh_kg_mean, dh_kg_std, dh_kg_min, dh_kg_max) = calculate_stats(&dh_key_gen_times);
    
    println!("\n--- KEY GENERATION PERFORMANCE ---");
    println!("{:<20} {:<15} {:<15} {:<15} {:<15} {:<15}", "Algorithm", "Mean", "Std Dev", "Min", "Max", "Throughput");
    println!("{}", "-".repeat(100));
    println!("{:<20} {:<15.2?} {:<15.2?} {:<15.2?} {:<15.2?} {:<15.1} keys/s", 
             "Swoosh (PQ)", swoosh_kg_mean, swoosh_kg_std, swoosh_kg_min, swoosh_kg_max,
             1.0 / swoosh_kg_mean.as_secs_f64());
    println!("{:<20} {:<15.2?} {:<15.2?} {:<15.2?} {:<15.2?} {:<15.1} keys/s", 
             "X25519 (Classic)", dh_kg_mean, dh_kg_std, dh_kg_min, dh_kg_max,
             1.0 / dh_kg_mean.as_secs_f64());
    
    let kg_speedup = swoosh_kg_mean.as_nanos() as f64 / dh_kg_mean.as_nanos() as f64;
    println!("\n• X25519 key generation is {:.1}x faster than Swoosh", kg_speedup);
    println!("• Swoosh key generation overhead: {:.1}%", (kg_speedup - 1.0) * 100.0);
    
    // Analyze key sizes
    let swoosh_public_size = swoosh_keypairs[0].0.public_key().serialize().len();
    let swoosh_private_size = swoosh_keypairs[0].0.private_key().serialize().len();
    let dh_public_size = dh_keypairs[0].0.public_key.serialize().len();
    let dh_private_size = dh_keypairs[0].0.private_key.serialize().len();
    
    println!("\n--- KEY SIZE ANALYSIS ---");
    println!("{:<20} {:<15} {:<15} {:<15}", "Algorithm", "Public Key", "Private Key", "Total");
    println!("{}", "-".repeat(65));
    println!("{:<20} {:<15} {:<15} {:<15}", 
             "Swoosh (PQ)", format_bytes(swoosh_public_size), format_bytes(swoosh_private_size), 
             format_bytes(swoosh_public_size + swoosh_private_size));
    println!("{:<20} {:<15} {:<15} {:<15}", 
             "X25519 (Classic)", format_bytes(dh_public_size), format_bytes(dh_private_size),
             format_bytes(dh_public_size + dh_private_size));
    
    let public_overhead = swoosh_public_size as f64 / dh_public_size as f64;
    let private_overhead = swoosh_private_size as f64 / dh_private_size as f64;
    let total_overhead = (swoosh_public_size + swoosh_private_size) as f64 / (dh_public_size + dh_private_size) as f64;
    
    println!("\n• Swoosh public key is {:.1}x larger than X25519", public_overhead);
    println!("• Swoosh private key is {:.1}x larger than X25519", private_overhead);
    println!("• Total Swoosh key material is {:.1}x larger than X25519", total_overhead);
    
    // Warmup phase
    println!("\n=== PHASE 2: WARMUP ({} iterations) ===", warmup_iterations);
    for i in 0..warmup_iterations {
        let keypair_idx = i % num_keypairs;
        
        // Swoosh warmup
        let (alice_swoosh, bob_swoosh) = &swoosh_keypairs[keypair_idx];
        let _ = alice_swoosh.derive_shared_secret(bob_swoosh.public_key(), true);
        let _ = bob_swoosh.derive_shared_secret(alice_swoosh.public_key(), false);
        
        // DH warmup
        let (alice_dh, bob_dh) = &dh_keypairs[keypair_idx];
        let _ = alice_dh.calculate_agreement(&bob_dh.public_key);
        let _ = bob_dh.calculate_agreement(&alice_dh.public_key);
    }
    
    println!("Warmup completed. Starting main benchmark...");
    
    // Main benchmark phase
    println!("\n=== PHASE 3: SHARED SECRET DERIVATION BENCHMARKS ===");
    
    for i in 0..num_iterations {
        if i % 100 == 0 && i > 0 {
            println!("Completed {}/{} iterations ({:.1}%)", i, num_iterations, (i as f64 / num_iterations as f64) * 100.0);
        }
        
        let keypair_idx = i % num_keypairs;
        
        // Benchmark Swoosh shared secret derivation
        let (alice_swoosh, bob_swoosh) = &swoosh_keypairs[keypair_idx];
        
        let start = Instant::now();
        let alice_swoosh_secret = alice_swoosh.derive_shared_secret(bob_swoosh.public_key(), true)
            .expect("Swoosh shared secret derivation should succeed");
        let swoosh_time = start.elapsed();
        swoosh_times.push(swoosh_time);
        
        // Verify Swoosh bidirectional derivation (only for first few iterations to avoid overhead)
        if i < 10 {
            let bob_swoosh_secret = bob_swoosh.derive_shared_secret(alice_swoosh.public_key(), false)
                .expect("Swoosh shared secret derivation should succeed");
            assert_eq!(alice_swoosh_secret, bob_swoosh_secret, 
                      "Swoosh shared secrets should match between Alice and Bob");
        }
        
        // Benchmark Diffie-Hellman shared secret derivation
        let (alice_dh, bob_dh) = &dh_keypairs[keypair_idx];
        
        let start = Instant::now();
        let alice_dh_secret = alice_dh.calculate_agreement(&bob_dh.public_key)
            .expect("DH key agreement should succeed");
        let dh_time = start.elapsed();
        dh_times.push(dh_time);
        
        // Verify DH bidirectional derivation (only for first few iterations to avoid overhead)
        if i < 10 {
            let bob_dh_secret = bob_dh.calculate_agreement(&alice_dh.public_key)
                .expect("DH key agreement should succeed");
            assert_eq!(alice_dh_secret.as_ref(), bob_dh_secret.as_ref(), 
                      "DH shared secrets should match between Alice and Bob");
        }
        
        // Verify shared secret sizes (only for first iteration)
        if i == 0 {
            println!("• Swoosh shared secret size: {} bytes", alice_swoosh_secret.len());
            println!("• X25519 shared secret size: {} bytes", alice_dh_secret.len());
        }
    }
    
    println!("Completed {}/{} iterations (100.0%)", num_iterations, num_iterations);
    
    // Calculate and display results
    let (swoosh_mean, swoosh_std, swoosh_min, swoosh_max) = calculate_stats(&swoosh_times);
    let (dh_mean, dh_std, dh_min, dh_max) = calculate_stats(&dh_times);
    
    println!("\n=== SHARED SECRET DERIVATION PERFORMANCE RESULTS ===");
    println!("{:<20} {:<15} {:<15} {:<15} {:<15} {:<15}", "Algorithm", "Mean", "Std Dev", "Min", "Max", "Throughput");
    println!("{}", "-".repeat(100));
    println!("{:<20} {:<15.2?} {:<15.2?} {:<15.2?} {:<15.2?} {:<15.1} ops/s", 
             "Swoosh (PQ)", swoosh_mean, swoosh_std, swoosh_min, swoosh_max,
             1.0 / swoosh_mean.as_secs_f64());
    println!("{:<20} {:<15.2?} {:<15.2?} {:<15.2?} {:<15.2?} {:<15.1} ops/s", 
             "X25519 (Classic)", dh_mean, dh_std, dh_min, dh_max,
             1.0 / dh_mean.as_secs_f64());
    
    // Performance analysis
    let speedup = swoosh_mean.as_nanos() as f64 / dh_mean.as_nanos() as f64;
    let efficiency = dh_mean.as_nanos() as f64 / swoosh_mean.as_nanos() as f64;
    
    println!("\n=== PERFORMANCE ANALYSIS ===");
    if speedup > 1.0 {
        println!("• X25519 is {:.1}x FASTER than Swoosh for shared secret derivation", speedup);
        println!("• Swoosh performance overhead: {:.1}%", (speedup - 1.0) * 100.0);
    } else {
        println!("• Swoosh is {:.1}x FASTER than X25519 for shared secret derivation", efficiency);
        println!("• Swoosh performance advantage: {:.1}%", (efficiency - 1.0) * 100.0);
    }
    
    // Calculate variance and consistency metrics
    let swoosh_cv = (swoosh_std.as_nanos() as f64 / swoosh_mean.as_nanos() as f64) * 100.0;
    let dh_cv = (dh_std.as_nanos() as f64 / dh_mean.as_nanos() as f64) * 100.0;
    
    println!("• Swoosh coefficient of variation: {:.2}% (consistency metric)", swoosh_cv);
    println!("• X25519 coefficient of variation: {:.2}% (consistency metric)", dh_cv);
    
    if swoosh_cv < dh_cv {
        println!("• Swoosh has MORE consistent performance ({:.1}% more stable)", dh_cv - swoosh_cv);
    } else {
        println!("• X25519 has MORE consistent performance ({:.1}% more stable)", swoosh_cv - dh_cv);
    }
    
    // Theoretical throughput calculations
    let swoosh_theoretical_throughput = 1.0 / swoosh_mean.as_secs_f64();
    let dh_theoretical_throughput = 1.0 / dh_mean.as_secs_f64();
    
    println!("\n=== THEORETICAL THROUGHPUT ANALYSIS ===");
    println!("• Swoosh: {:.0} shared secrets per second", swoosh_theoretical_throughput);
    println!("• X25519: {:.0} shared secrets per second", dh_theoretical_throughput);
    
    // Per-hour and per-day calculations
    let swoosh_per_hour = swoosh_theoretical_throughput * 3600.0;
    let dh_per_hour = dh_theoretical_throughput * 3600.0;
    let swoosh_per_day = swoosh_per_hour * 24.0;
    let dh_per_day = dh_per_hour * 24.0;
    
    println!("• Swoosh: {:.0} shared secrets per hour, {:.0} per day", swoosh_per_hour, swoosh_per_day);
    println!("• X25519: {:.0} shared secrets per hour, {:.0} per day", dh_per_hour, dh_per_day);
    
    // Distribution analysis (percentiles)
    let swoosh_sorted = get_percentiles(&swoosh_times);
    let dh_sorted = get_percentiles(&dh_times);
    
    println!("\n=== LATENCY DISTRIBUTION (Percentiles) ===");
    println!("{:<12} {:<15} {:<15}", "Percentile", "Swoosh", "X25519");
    println!("{}", "-".repeat(45));
    println!("{:<12} {:<15.2?} {:<15.2?}", "P50 (median)", swoosh_sorted.p50, dh_sorted.p50);
    println!("{:<12} {:<15.2?} {:<15.2?}", "P90", swoosh_sorted.p90, dh_sorted.p90);
    println!("{:<12} {:<15.2?} {:<15.2?}", "P95", swoosh_sorted.p95, dh_sorted.p95);
    println!("{:<12} {:<15.2?} {:<15.2?}", "P99", swoosh_sorted.p99, dh_sorted.p99);
    println!("{:<12} {:<15.2?} {:<15.2?}", "P99.9", swoosh_sorted.p999, dh_sorted.p999);
    
    // Security and trade-off analysis
    println!("\n=== SECURITY AND TRADE-OFF ANALYSIS ===");
    println!("• Swoosh (Post-Quantum):");
    println!("✗ Larger key sizes ({:.1}x)", total_overhead);
    if speedup > 1.0 {
        println!("✗ Slower performance ({:.1}x)", speedup);
    } else {
        println!("✓ Faster performance ({:.1}x)", efficiency);
    }
    
    // Memory usage analysis
    let swoosh_memory_per_op = (swoosh_public_size + swoosh_private_size) * 2; // Alice + Bob
    let dh_memory_per_op = (dh_public_size + dh_private_size) * 2; // Alice + Bob
    
    println!("\n=== MEMORY USAGE ANALYSIS ===");
    println!("• Swoosh memory per key agreement: {} bytes", format_bytes(swoosh_memory_per_op));
    println!("• X25519 memory per key agreement: {} bytes", format_bytes(dh_memory_per_op));
    println!("• Swoosh memory overhead: {:.1}x ({:.0}% more memory)", 
             swoosh_memory_per_op as f64 / dh_memory_per_op as f64,
             ((swoosh_memory_per_op as f64 / dh_memory_per_op as f64) - 1.0) * 100.0);
    
    // Energy efficiency estimation (rough calculation based on time)
    println!("\n=== ENERGY EFFICIENCY ESTIMATION ===");
    println!("(Based on execution time as proxy for CPU cycles)");
    let swoosh_energy_ratio = swoosh_mean.as_nanos() as f64 / dh_mean.as_nanos() as f64;
    if swoosh_energy_ratio > 1.0 {
        println!("• Swoosh consumes ~{:.1}x more energy per operation", swoosh_energy_ratio);
    } else {
        println!("• Swoosh consumes ~{:.1}x less energy per operation", 1.0 / swoosh_energy_ratio);
    }
    
    // Conclusion
    println!("\n=== BENCHMARK CONCLUSION ===");
    println!("✓ Benchmarked {} shared secret derivations per algorithm", num_iterations);
    println!("✓ Used {} different key pairs", num_keypairs);
    println!("✓ Verified bidirectional shared secret agreement");
    println!("✓ Both algorithms function correctly and consistently");
    
    if speedup > 2.0 {
        println!("• Significant performance difference detected ({:.1}x)", speedup);
    } else if speedup > 1.2 {
        println!("• Moderate performance difference detected ({:.1}x)", speedup);
    } else {
        println!("• Performance is relatively comparable");
    }
    
    Ok(())
}

/// Calculate statistical measures for a set of duration measurements
fn calculate_stats(times: &[Duration]) -> (Duration, Duration, Duration, Duration) {
    let mut sorted_times = times.to_vec();
    sorted_times.sort();
    
    let mean_nanos = times.iter().map(|d| d.as_nanos()).sum::<u128>() / times.len() as u128;
    let mean = Duration::from_nanos(mean_nanos as u64);
    
    // Calculate standard deviation
    let variance = times.iter()
        .map(|d| {
            let diff = d.as_nanos() as i128 - mean_nanos as i128;
            (diff * diff) as u128
        })
        .sum::<u128>() / times.len() as u128;
    let std_dev = Duration::from_nanos((variance as f64).sqrt() as u64);
    
    let min = sorted_times[0];
    let max = sorted_times[times.len() - 1];
    
    (mean, std_dev, min, max)
}

/// Calculate percentiles for latency distribution analysis
struct Percentiles {
    p50: Duration,  // Median
    p90: Duration,
    p95: Duration,
    p99: Duration,
    p999: Duration, // 99.9th percentile
}

fn get_percentiles(times: &[Duration]) -> Percentiles {
    let mut sorted = times.to_vec();
    sorted.sort();
    let len = sorted.len();
    
    Percentiles {
        p50: sorted[len * 50 / 100],
        p90: sorted[len * 90 / 100],
        p95: sorted[len * 95 / 100],
        p99: sorted[len * 99 / 100],
        p999: sorted[len * 999 / 1000],
    }
}

/// Format bytes in human-readable format
fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_correctness() {
        let mut csprng = rand::rng();
        
        // Test Swoosh shared secret derivation
        let alice_swoosh = SwooshKeyPair::generate(true);
        let bob_swoosh = SwooshKeyPair::generate(false);
        
        let alice_secret = alice_swoosh.derive_shared_secret(bob_swoosh.public_key(), true)
            .expect("Swoosh derivation should work");
        let bob_secret = bob_swoosh.derive_shared_secret(alice_swoosh.public_key(), false)
            .expect("Swoosh derivation should work");
        
        assert_eq!(alice_secret, bob_secret, "Swoosh secrets should match");
        
        // Test DH shared secret derivation
        let alice_dh = KeyPair::generate(&mut csprng);
        let bob_dh = KeyPair::generate(&mut csprng);
        
        let alice_dh_secret = alice_dh.calculate_agreement(&bob_dh.public_key)
            .expect("DH agreement should work");
        let bob_dh_secret = bob_dh.calculate_agreement(&alice_dh.public_key)
            .expect("DH agreement should work");
        
        assert_eq!(alice_dh_secret.as_ref(), bob_dh_secret.as_ref(), "DH secrets should match");
        
        println!("✓ Both algorithms produce matching bidirectional shared secrets");
    }
    
    #[test]
    fn test_key_sizes() {
        let mut csprng = rand::rng();
        
        // Check Swoosh key sizes
        let swoosh_keypair = SwooshKeyPair::generate(true);
        let swoosh_public_size = swoosh_keypair.public_key().serialize().len();
        let swoosh_private_size = swoosh_keypair.private_key().serialize().len();
        
        // Check DH key sizes
        let dh_keypair = KeyPair::generate(&mut csprng);
        let dh_public_size = dh_keypair.public_key.serialize().len();
        let dh_private_size = dh_keypair.private_key.serialize().len();
        
        println!("Key size comparison:");
        println!("• Swoosh: {} public + {} private = {} total", 
                 swoosh_public_size, swoosh_private_size, swoosh_public_size + swoosh_private_size);
        println!("• X25519: {} public + {} private = {} total", 
                 dh_public_size, dh_private_size, dh_public_size + dh_private_size);
        
        // Swoosh should have larger keys (post-quantum overhead)
        assert!(swoosh_public_size > dh_public_size, "Swoosh public key should be larger");
        assert!(swoosh_private_size > dh_private_size, "Swoosh private key should be larger");
    }
    
    #[test]
    fn test_shared_secret_sizes() {
        let mut csprng = rand::rng();
        
        // Test Swoosh secret size
        let alice_swoosh = SwooshKeyPair::generate(true);
        let bob_swoosh = SwooshKeyPair::generate(false);
        let swoosh_secret = alice_swoosh.derive_shared_secret(bob_swoosh.public_key(), true)
            .expect("Swoosh derivation should work");
        
        // Test DH secret size
        let alice_dh = KeyPair::generate(&mut csprng);
        let bob_dh = KeyPair::generate(&mut csprng);
        let dh_secret = alice_dh.calculate_agreement(&bob_dh.public_key)
            .expect("DH agreement should work");
        
        println!("Shared secret sizes:");
        println!("• Swoosh: {} bytes", swoosh_secret.len());
        println!("• X25519: {} bytes", dh_secret.len());
        
        // Both should produce 32-byte secrets (standard for symmetric cryptography)
        assert_eq!(swoosh_secret.len(), 32, "Swoosh should produce 32-byte secret");
        assert_eq!(dh_secret.len(), 32, "X25519 should produce 32-byte secret");
    }
    
    #[test]
    fn test_deterministic_derivation() {
        // Test that same keys produce same shared secret (deterministic)
        let alice_swoosh = SwooshKeyPair::generate(true);
        let bob_swoosh = SwooshKeyPair::generate(false);
        
        let secret1 = alice_swoosh.derive_shared_secret(bob_swoosh.public_key(), true)
            .expect("First derivation should work");
        let secret2 = alice_swoosh.derive_shared_secret(bob_swoosh.public_key(), true)
            .expect("Second derivation should work");
        
        assert_eq!(secret1, secret2, "Swoosh derivation should be deterministic");
        
        let mut csprng = rand::rng();
        let alice_dh = KeyPair::generate(&mut csprng);
        let bob_dh = KeyPair::generate(&mut csprng);
        
        let dh_secret1 = alice_dh.calculate_agreement(&bob_dh.public_key)
            .expect("First DH agreement should work");
        let dh_secret2 = alice_dh.calculate_agreement(&bob_dh.public_key)
            .expect("Second DH agreement should work");
        
        assert_eq!(dh_secret1.as_ref(), dh_secret2.as_ref(), "DH derivation should be deterministic");
        
        println!("✓ Both algorithms are deterministic (same inputs → same outputs)");
    }
    
    #[test]
    fn test_performance_measurement_accuracy() {
        // Test that our timing measurements are reasonable
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(1)); // Sleep for 1ms
        let elapsed = start.elapsed();
        
        // Should be approximately 1ms (allow for some variance)
        assert!(elapsed >= Duration::from_millis(1), "Timer should measure at least 1ms");
        assert!(elapsed < Duration::from_millis(10), "Timer should not be wildly inaccurate");
        
        println!("✓ Timing measurement accuracy verified: {:?}", elapsed);
    }
}
