use libsignal_protocol::*;
use rand::{rng, RngCore};
use std::time::SystemTime;

fn main() -> Result<(), SignalProtocolError> {
    use std::thread;
    
    // Create a thread with larger stack to run the async main
    let handle = thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32MB stack
        .spawn(|| {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async_main())
        })
        .unwrap();
    
    handle.join().unwrap()
}

async fn async_main() -> Result<(), SignalProtocolError> {
    // Initialize random number generator
    let mut csprng = rng();
    println!("=== SIGNAL PROTOCOL COMMUNICATION EXAMPLE (WITHOUT POST-QUANTUM) ===");
    // Create addresses for Alice and Bob
    let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14151112222".to_owned(), 1.into());
    
    // Generate identity key pairs for both parties
    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);
    
    println!("=== IDENTITY KEYS ===");
    println!("Alice Identity Public Key: {:?}", hex::encode(alice_identity.identity_key().serialize()));
    println!("Bob Identity Public Key: {:?}", hex::encode(bob_identity.identity_key().serialize()));
    
    // Create in-memory stores for both parties
    let mut alice_store = InMemSignalProtocolStore::new(alice_identity, csprng.next_u32(), true)?;
    let mut bob_store = InMemSignalProtocolStore::new(bob_identity, csprng.next_u32(), false)?;
    
    // Generate Bob's signed pre-key
    let bob_signed_prekey_pair = KeyPair::generate(&mut csprng);
    let bob_signed_prekey_id = SignedPreKeyId::from(1u32);
    let bob_signed_prekey_signature = bob_identity
        .private_key()
        .calculate_signature(&bob_signed_prekey_pair.public_key.serialize(), &mut csprng)?;
    
    let bob_signed_prekey = SignedPreKeyRecord::new(
        bob_signed_prekey_id,
        Timestamp::from_epoch_millis(0),
        &bob_signed_prekey_pair,
        &bob_signed_prekey_signature,
    );
    
    println!("\n=== BOB'S SIGNED PRE-KEY ===");
    println!("Signed Pre-Key ID: {:?}", bob_signed_prekey_id);
    println!("Signed Pre-Key Public: {:?}", hex::encode(bob_signed_prekey_pair.public_key.serialize()));
    println!("Signed Pre-Key Signature: {:?}", hex::encode(&bob_signed_prekey_signature));
    
    // Store Bob's signed pre-key
    bob_store.save_signed_pre_key(bob_signed_prekey_id, &bob_signed_prekey).await?;
    
    // Optional: Generate one-time pre-key for Bob
    let bob_prekey_pair = KeyPair::generate(&mut csprng);
    let bob_prekey_id = PreKeyId::from(1u32);
    let bob_prekey = PreKeyRecord::new(bob_prekey_id, &bob_prekey_pair);
    
    println!("\n=== BOB'S ONE-TIME PRE-KEY ===");
    println!("One-Time Pre-Key ID: {:?}", bob_prekey_id);
    println!("One-Time Pre-Key Public: {:?}", hex::encode(bob_prekey_pair.public_key.serialize()));
    
    bob_store.save_pre_key(bob_prekey_id, &bob_prekey).await?;
    
    // Create pre-key bundle for Bob WITHOUT Kyber key
    let bob_prekey_bundle = PreKeyBundle::new(
        bob_store.get_local_registration_id().await?,
        1.into(), // device_id
        Some((bob_prekey_id, bob_prekey.public_key()?)),
        bob_signed_prekey_id,
        bob_signed_prekey.public_key()?,
        bob_signed_prekey.signature().unwrap(),
        *bob_identity.identity_key(),
    )?;
    
    println!("\n=== PRE-KEY BUNDLE CREATED (WITHOUT KYBER) ===");
    println!("Registration ID: {:?}", bob_store.get_local_registration_id().await?);
    
    // Alice processes Bob's pre-key bundle to establish session WITHOUT PQ ratchet
    // Alice session is initialized and initial double ratchet keys established
    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_prekey_bundle,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
        UsePQRatchet::No,
    ).await?;
    
    println!("\n=== SESSION ESTABLISHED (NO POST-QUANTUM) ===");
    
    // Alice encrypts a message to Bob
    let alice_message = "Hello Bob! This is Alice.";
    let alice_ciphertext = message_encrypt(
        alice_message.as_bytes(),
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    ).await?;
    
    println!("\n=== ALICE'S MESSAGE ===");
    println!("Alice sent: {}", alice_message);
    println!("Ciphertext type: {:?}", alice_ciphertext.message_type());
    println!("Ciphertext length: {} bytes", alice_ciphertext.serialize().len());
    //println!("Encrypted message: {:?}", hex::encode(alice_ciphertext.serialize()));
    
    // Bob decrypts Alice's message - correct usage
    let bob_plaintext = match &alice_ciphertext {
        CiphertextMessage::PreKeySignalMessage(prekey_msg) => {
            println!("\n=== DECRYPTING PRE-KEY MESSAGE ===");
            message_decrypt_prekey(
                prekey_msg,
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &mut bob_store.pre_key_store,
                &mut bob_store.signed_pre_key_store,
                &mut bob_store.kyber_pre_key_store,
                &mut bob_store.swoosh_pre_key_store,
                &mut csprng,
                UsePQRatchet::No,
            ).await?
        },
        CiphertextMessage::SignalMessage(signal_msg) => {
            println!("\n=== DECRYPTING SIGNAL MESSAGE ===");
            message_decrypt_signal(
                signal_msg,
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &mut csprng,
            ).await?
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Unexpected message type")),
    };
    
    let decrypted_message = String::from_utf8(bob_plaintext).expect("Valid UTF-8");
    println!("Bob received: {}", decrypted_message);
    
    // Now Bob can reply to Alice (session is established)
    let bob_reply = "Hello Alice! Nice to hear from you.";
    let bob_ciphertext = message_encrypt(
        bob_reply.as_bytes(),
        &alice_address,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    ).await?;
    
    println!("\n=== BOB'S REPLY ===");
    println!("Bob sent: {}", bob_reply);
    println!("Reply ciphertext type: {:?}", bob_ciphertext.message_type());
    println!("Reply ciphertext length: {} bytes", bob_ciphertext.serialize().len());
    //println!("Encrypted reply: {:?}", hex::encode(bob_ciphertext.serialize()));
    
    // Alice decrypts Bob's reply (should be SignalMessage after first exchange)
    let alice_received = match &bob_ciphertext {
        CiphertextMessage::SignalMessage(signal_msg) => {
            println!("\n=== ALICE DECRYPTING BOB'S REPLY ===");
            message_decrypt_signal(
                signal_msg,
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &mut csprng,
            ).await?
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected SignalMessage")),
    };
    
    let alice_decrypted_reply = String::from_utf8(alice_received).expect("Valid UTF-8");
    println!("Alice received: {}", alice_decrypted_reply);
    
    // Continue the conversation - Alice sends another message (Turn 3)
    let alice_second_message = "Thanks Bob! How's the classic cryptography working for you?";
    let alice_second_ciphertext = message_encrypt(
        alice_second_message.as_bytes(),
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    ).await?;
    
    println!("\n=== ALICE'S SECOND MESSAGE (Turn 3) ===");
    println!("Alice sent: {}", alice_second_message);
    println!("Ciphertext type: {:?}", alice_second_ciphertext.message_type());
    println!("Ciphertext length: {} bytes", alice_second_ciphertext.serialize().len());
    //println!("Encrypted message: {:?}", hex::encode(alice_second_ciphertext.serialize()));
    
    // Bob decrypts Alice's second message
    let bob_second_plaintext = match &alice_second_ciphertext {
        CiphertextMessage::SignalMessage(signal_msg) => {
            println!("\n=== BOB DECRYPTING ALICE'S SECOND MESSAGE ===");
            message_decrypt_signal(
                signal_msg,
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &mut csprng,
            ).await?
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected SignalMessage")),
    };
    
    let bob_decrypted_second = String::from_utf8(bob_second_plaintext).expect("Valid UTF-8");
    println!("Bob received: {}", bob_decrypted_second);
    
    // Bob sends another reply (Turn 4)
    let bob_second_reply = "It's reliable! The ECDH X25519 provides excellent forward secrecy without quantum overhead.";
    let bob_second_ciphertext = message_encrypt(
        bob_second_reply.as_bytes(),
        &alice_address,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    ).await?;
    
    println!("\n=== BOB'S SECOND REPLY (Turn 4) ===");
    println!("Bob sent: {}", bob_second_reply);
    println!("Reply ciphertext type: {:?}", bob_second_ciphertext.message_type());
    println!("Reply ciphertext length: {} bytes", bob_second_ciphertext.serialize().len());
    //println!("Encrypted reply: {:?}", hex::encode(bob_second_ciphertext.serialize()));
    
    // Alice decrypts Bob's second reply
    let alice_second_received = match &bob_second_ciphertext {
        CiphertextMessage::SignalMessage(signal_msg) => {
            println!("\n=== ALICE DECRYPTING BOB'S SECOND REPLY ===");
            message_decrypt_signal(
                signal_msg,
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &mut csprng,
            ).await?
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected SignalMessage")),
    };
    
    let alice_decrypted_second_reply = String::from_utf8(alice_second_received).expect("Valid UTF-8");
    println!("Alice received reply: {}", alice_decrypted_second_reply);
    
    println!("\n=== COMMUNICATION COMPLETE ===");
    println!("Communication established successfully!");
    println!("Total double ratchet turns: 4");
    println!("Messages exchanged: 4 (2 from Alice, 2 from Bob)");
    println!("Using classic cryptography (no post-quantum)");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn benchmark_no_pq_performance() -> Result<(), SignalProtocolError> {
        println!("\n=== CLASSIC CRYPTOGRAPHY PERFORMANCE BENCHMARKING ===");
        
        use std::time::{Duration, Instant};
        use std::collections::HashMap;
        
        let mut csprng = rand::rng();
        
        // Different message sizes to test
        let message_sizes = vec![
            ("Tiny", 16),       // 16 bytes
            ("Small", 256),     // 256 bytes  
            ("Medium", 4096),   // 4KB
            ("Large", 65536),   // 64KB
            ("XLarge", 1048576), // 1MB
        ];
        
        let num_iterations = 100; // Number of iterations for each test
        let num_key_pairs = 50;   // Number of different key pairs to test
        
        println!("Running {} iterations with {} different key pairs each", num_iterations, num_key_pairs);
        println!("Message sizes: {:?}", message_sizes.iter().map(|(name, size)| format!("{}: {} bytes", name, size)).collect::<Vec<_>>());
        
        // Storage for benchmark results
        let mut results: HashMap<String, Vec<Duration>> = HashMap::new();
        
        for (size_name, message_size) in &message_sizes {
            println!("\n--- Benchmarking with {} message size ({} bytes) ---", size_name, message_size);
            
            // Generate test message of specified size
            let test_message = "A".repeat(*message_size);
            
            for iteration in 0..num_iterations {
                if iteration % 20 == 0 {
                    println!("  Iteration {}/{}", iteration + 1, num_iterations);
                }
                
                // Generate fresh key pairs for each iteration
                let alice_address = ProtocolAddress::new(format!("+1415111{:04}", iteration), 1.into());
                let bob_address = ProtocolAddress::new(format!("+1415222{:04}", iteration), 1.into());
                
                let alice_identity = IdentityKeyPair::generate(&mut csprng);
                let bob_identity = IdentityKeyPair::generate(&mut csprng);
                
                let mut alice_store = InMemSignalProtocolStore::new(alice_identity, csprng.next_u32(), true)?;
                let mut bob_store = InMemSignalProtocolStore::new(bob_identity, csprng.next_u32(), false)?;
                
                // Generate Bob's keys
                let bob_signed_prekey_pair = KeyPair::generate(&mut csprng);
                let bob_signed_prekey_id = SignedPreKeyId::from((iteration + 1) as u32);
                let bob_signed_prekey_signature = bob_identity
                    .private_key()
                    .calculate_signature(&bob_signed_prekey_pair.public_key.serialize(), &mut csprng)?;
                
                let bob_signed_prekey = SignedPreKeyRecord::new(
                    bob_signed_prekey_id,
                    Timestamp::from_epoch_millis(0),
                    &bob_signed_prekey_pair,
                    &bob_signed_prekey_signature,
                );
                
                let bob_prekey_pair = KeyPair::generate(&mut csprng);
                let bob_prekey_id = PreKeyId::from((iteration + 1) as u32);
                let bob_prekey = PreKeyRecord::new(bob_prekey_id, &bob_prekey_pair);
                
                // Store Bob's keys
                bob_store.save_signed_pre_key(bob_signed_prekey_id, &bob_signed_prekey).await?;
                bob_store.save_pre_key(bob_prekey_id, &bob_prekey).await?;
                
                // Create pre-key bundle WITHOUT Kyber key (classic crypto only)
                let bob_prekey_bundle = PreKeyBundle::new(
                    bob_store.get_local_registration_id().await?,
                    1.into(),
                    Some((bob_prekey_id, bob_prekey.public_key()?)),
                    bob_signed_prekey_id,
                    bob_signed_prekey.public_key()?,
                    bob_signed_prekey.signature().unwrap(),
                    *bob_identity.identity_key(),
                )?;
                
                // BENCHMARK 1: Pre-key bundle processing (classic crypto)
                let start = Instant::now();
                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    &bob_prekey_bundle,
                    SystemTime::now(),
                    &mut csprng,
                    UsePQRatchet::No,
                ).await?;
                let prekey_bundle_time = start.elapsed();
                results.entry(format!("{}_prekey_bundle_processing", size_name))
                    .or_insert_with(Vec::new)
                    .push(prekey_bundle_time);
                
                // BENCHMARK 2: First message encryption (after prekey bundle)
                let start = Instant::now();
                let alice_ciphertext = message_encrypt(
                    test_message.as_bytes(),
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    SystemTime::now(),
                    &mut csprng,
                ).await?;
                let first_encrypt_time = start.elapsed();
                results.entry(format!("{}_first_message_encrypt", size_name))
                    .or_insert_with(Vec::new)
                    .push(first_encrypt_time);
                
                // BENCHMARK 3: Pre-key message decryption
                let start = Instant::now();
                let bob_plaintext = match &alice_ciphertext {
                    CiphertextMessage::PreKeySignalMessage(prekey_msg) => {
                        message_decrypt_prekey(
                            prekey_msg,
                            &alice_address,
                            &mut bob_store.session_store,
                            &mut bob_store.identity_store,
                            &mut bob_store.pre_key_store,
                            &mut bob_store.signed_pre_key_store,
                            &mut bob_store.kyber_pre_key_store,
                            &mut bob_store.swoosh_pre_key_store,
                            &mut csprng,
                            UsePQRatchet::No,
                        ).await?
                    },
                    _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected PreKeySignalMessage")),
                };
                let prekey_decrypt_time = start.elapsed();
                results.entry(format!("{}_prekey_message_decrypt", size_name))
                    .or_insert_with(Vec::new)
                    .push(prekey_decrypt_time);
                
                // Verify decryption
                assert_eq!(test_message.as_bytes(), bob_plaintext);
                
                // BENCHMARK 4: Subsequent message encryption (normal ratchet)
                let start = Instant::now();
                let bob_reply_ciphertext = message_encrypt(
                    test_message.as_bytes(),
                    &alice_address,
                    &mut bob_store.session_store,
                    &mut bob_store.identity_store,
                    SystemTime::now(),
                    &mut csprng,
                ).await?;
                let subsequent_encrypt_time = start.elapsed();
                results.entry(format!("{}_subsequent_message_encrypt", size_name))
                    .or_insert_with(Vec::new)
                    .push(subsequent_encrypt_time);
                
                // BENCHMARK 5: Normal signal message decryption
                let start = Instant::now();
                let alice_received = match &bob_reply_ciphertext {
                    CiphertextMessage::SignalMessage(signal_msg) => {
                        message_decrypt_signal(
                            signal_msg,
                            &bob_address,
                            &mut alice_store.session_store,
                            &mut alice_store.identity_store,
                            &mut csprng,
                        ).await?
                    },
                    _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected SignalMessage")),
                };
                let signal_decrypt_time = start.elapsed();
                results.entry(format!("{}_signal_message_decrypt", size_name))
                    .or_insert_with(Vec::new)
                    .push(signal_decrypt_time);
                
                // Verify decryption
                assert_eq!(test_message.as_bytes(), alice_received);
                
                // BENCHMARK 6: Multiple ratchet turns for performance stability
                for ratchet_turn in 0..5 {
                    // Alice encrypts
                    let start = Instant::now();
                    let alice_ratchet_msg = message_encrypt(
                        test_message.as_bytes(),
                        &bob_address,
                        &mut alice_store.session_store,
                        &mut alice_store.identity_store,
                        SystemTime::now(),
                        &mut csprng,
                    ).await?;
                    let alice_ratchet_encrypt_time = start.elapsed();
                    results.entry(format!("{}_ratchet_turn_{}_encrypt", size_name, ratchet_turn))
                        .or_insert_with(Vec::new)
                        .push(alice_ratchet_encrypt_time);
                    
                    // Bob decrypts
                    let start = Instant::now();
                    let _bob_ratchet_received = match &alice_ratchet_msg {
                        CiphertextMessage::SignalMessage(signal_msg) => {
                            message_decrypt_signal(
                                signal_msg,
                                &alice_address,
                                &mut bob_store.session_store,
                                &mut bob_store.identity_store,
                                &mut csprng,
                            ).await?
                        },
                        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected SignalMessage")),
                    };
                    let bob_ratchet_decrypt_time = start.elapsed();
                    results.entry(format!("{}_ratchet_turn_{}_decrypt", size_name, ratchet_turn))
                        .or_insert_with(Vec::new)
                        .push(bob_ratchet_decrypt_time);
                }
            }
        }
        
        // Calculate and display statistics
        println!("\n=== PERFORMANCE ANALYSIS RESULTS ===");
        
        fn calculate_stats(times: &[Duration]) -> (Duration, Duration, Duration, Duration) {
            let mut sorted_times = times.to_vec();
            sorted_times.sort();
            
            let mean = Duration::from_nanos(
                (times.iter().map(|d| d.as_nanos()).sum::<u128>() / times.len() as u128) as u64
            );
            
            let median = sorted_times[times.len() / 2];
            let min = sorted_times[0];
            let max = sorted_times[times.len() - 1];
            
            (mean, median, min, max)
        }
        
        // Group results by operation type
        let operations = vec![
            "prekey_bundle_processing",
            "first_message_encrypt", 
            "prekey_message_decrypt",
            "subsequent_message_encrypt",
            "signal_message_decrypt"
        ];
        
        for operation in &operations {
            println!("\n--- {} ---", operation.replace('_', " ").to_uppercase());
            println!("{:<12} {:<12} {:<12} {:<12} {:<12} {:<15}", "Size", "Mean", "Median", "Min", "Max", "Throughput");
            println!("{}", "-".repeat(75));
            
            for (size_name, message_size) in &message_sizes {
                let key = format!("{}_{}", size_name, operation);
                if let Some(times) = results.get(&key) {
                    let (mean, median, min, max) = calculate_stats(times);
                    
                    // Calculate throughput (MB/s for encryption/decryption operations)
                    let throughput = if operation.contains("encrypt") || operation.contains("decrypt") {
                        let mb_per_second = (*message_size as f64) / (1024.0 * 1024.0) / mean.as_secs_f64();
                        format!("{:.2} MB/s", mb_per_second)
                    } else {
                        "N/A".to_string()
                    };
                    
                    println!("{:<12} {:<12.2?} {:<12.2?} {:<12.2?} {:<12.2?} {:<15}", 
                             size_name, mean, median, min, max, throughput);
                }
            }
        }
        
        // Display ratchet performance
        println!("\n--- RATCHET TURN PERFORMANCE ---");
        for ratchet_turn in 0..5 {
            println!("\n  Ratchet Turn {} (Encrypt/Decrypt):", ratchet_turn);
            println!("  {:<12} {:<15} {:<15}", "Size", "Encrypt", "Decrypt");
            println!("  {}", "-".repeat(45));
            
            for (size_name, _) in &message_sizes {
                let encrypt_key = format!("{}_ratchet_turn_{}_encrypt", size_name, ratchet_turn);
                let decrypt_key = format!("{}_ratchet_turn_{}_decrypt", size_name, ratchet_turn);
                
                if let (Some(encrypt_times), Some(decrypt_times)) = (results.get(&encrypt_key), results.get(&decrypt_key)) {
                    let (encrypt_mean, _, _, _) = calculate_stats(encrypt_times);
                    let (decrypt_mean, _, _, _) = calculate_stats(decrypt_times);
                    
                    println!("  {:<12} {:<15.2?} {:<15.2?}", size_name, encrypt_mean, decrypt_mean);
                }
            }
        }
        
        // Performance insights for classic cryptography
        println!("\n=== CLASSIC CRYPTOGRAPHY PERFORMANCE INSIGHTS ===");
        
        // Compare prekey vs normal operations
        for (size_name, _) in &message_sizes {
            if let (Some(prekey_times), Some(signal_times)) = (
                results.get(&format!("{}_prekey_message_decrypt", size_name)),
                results.get(&format!("{}_signal_message_decrypt", size_name))
            ) {
                let (prekey_mean, _, _, _) = calculate_stats(prekey_times);
                let (signal_mean, _, _, _) = calculate_stats(signal_times);
                let overhead = (prekey_mean.as_nanos() as f64 / signal_mean.as_nanos() as f64) - 1.0;
                
                println!("• {} messages: Pre-key decryption is {:.1}% slower than signal decryption", 
                         size_name, overhead * 100.0);
            }
        }
        
        // Encryption vs decryption comparison
        for (size_name, _) in &message_sizes {
            if let (Some(encrypt_times), Some(decrypt_times)) = (
                results.get(&format!("{}_subsequent_message_encrypt", size_name)),
                results.get(&format!("{}_signal_message_decrypt", size_name))
            ) {
                let (encrypt_mean, _, _, _) = calculate_stats(encrypt_times);
                let (decrypt_mean, _, _, _) = calculate_stats(decrypt_times);
                let ratio = encrypt_mean.as_nanos() as f64 / decrypt_mean.as_nanos() as f64;
                
                println!("• {} messages: Encryption is {:.1}x {} than decryption", 
                         size_name, ratio.abs(), if ratio > 1.0 { "slower" } else { "faster" });
            }
        }
        
        // Bundle processing cost
        if let Some(bundle_times) = results.get("Tiny_prekey_bundle_processing") {
            let (bundle_mean, _, _, _) = calculate_stats(bundle_times);
            println!("• Pre-key bundle processing takes {:.2?} on average", bundle_mean);
        }
        
        // Classic crypto specific insights
        println!("• Using classic ECDH X25519 without post-quantum overhead");
        println!("• Performance baseline for comparison with post-quantum variants");
        println!("• Optimal performance for current non-quantum-resistant scenarios");
        
        println!("\n🎉 Classic Cryptography Benchmarking completed!");
        println!("Total operations benchmarked: {}", results.len());
        println!("Total measurements taken: {}", results.values().map(|v| v.len()).sum::<usize>());
        
        Ok(())
    }
}
