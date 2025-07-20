
use libsignal_protocol::*;
use rand::{rng, RngCore};
use std::time::SystemTime;

fn main() -> Result<(), SignalProtocolError> {
    use std::thread;
    
    // Create a thread with larger stack to run the async main
    let handle = thread::Builder::new()
        .stack_size(100 * 1024 * 1024) // 100MB stack
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
    println!("=== SIGNAL PROTOCOL COMMUNICATION EXAMPLE ===");
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
    
    // Generate Bob's Kyber pre-key
    let bob_kyber_keypair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);
    let bob_kyber_prekey_id = KyberPreKeyId::from(1u32);
    let bob_kyber_prekey_signature = bob_identity
        .private_key()
        .calculate_signature(&bob_kyber_keypair.public_key.serialize(), &mut csprng)?;
    
    let bob_kyber_prekey = KyberPreKeyRecord::new(
        bob_kyber_prekey_id,
        Timestamp::from_epoch_millis(0),
        &bob_kyber_keypair,
        &bob_kyber_prekey_signature,
    );
    
    println!("\n=== BOB'S KYBER PRE-KEY (Post-Quantum) ===");
    println!("Kyber Pre-Key ID: {:?}", bob_kyber_prekey_id);
    println!("Kyber Public Key Length: {} bytes", bob_kyber_keypair.public_key.serialize().len());
    //println!("Kyber Public Key: {:?}", hex::encode(bob_kyber_keypair.public_key.serialize()));
    println!("Kyber Pre-Key Signature: {:?}", hex::encode(&bob_kyber_prekey_signature));
    
    // Store Bob's pre-keys
    bob_store.save_signed_pre_key(bob_signed_prekey_id, &bob_signed_prekey).await?;
    bob_store.save_kyber_pre_key(bob_kyber_prekey_id, &bob_kyber_prekey).await?;
    
    // Optional: Generate one-time pre-key for Bob
    let bob_prekey_pair = KeyPair::generate(&mut csprng);
    let bob_prekey_id = PreKeyId::from(1u32);
    let bob_prekey = PreKeyRecord::new(bob_prekey_id, &bob_prekey_pair);
    
    println!("\n=== BOB'S ONE-TIME PRE-KEY ===");
    println!("One-Time Pre-Key ID: {:?}", bob_prekey_id);
    println!("One-Time Pre-Key Public: {:?}", hex::encode(bob_prekey_pair.public_key.serialize()));
    
    bob_store.save_pre_key(bob_prekey_id, &bob_prekey).await?;
    
    // Create pre-key bundle for Bob with Kyber key
    let bob_prekey_bundle = PreKeyBundle::new(
        bob_store.get_local_registration_id().await?,
        1.into(), // device_id
        Some((bob_prekey_id, bob_prekey.public_key()?)),
        bob_signed_prekey_id,
        bob_signed_prekey.public_key()?,
        bob_signed_prekey.signature().unwrap(),
        *bob_identity.identity_key(),
    )?
    .with_kyber_pre_key(
        bob_kyber_prekey_id,
        bob_kyber_prekey.public_key().unwrap(),
        bob_kyber_prekey.signature().unwrap(),
    );
    
    println!("\n=== PRE-KEY BUNDLE CREATED ===");
    println!("Registration ID: {:?}", bob_store.get_local_registration_id().await?);
    
    // Alice processes Bob's pre-key bundle to establish session
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
    
    println!("\n=== SESSION ESTABLISHED ===");
    
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
    println!("Encrypted reply: {:?}", hex::encode(bob_ciphertext.serialize()));
    
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
    let alice_second_message = "Thanks Bob! How's the post-quantum cryptography working for you?";
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
    println!("Encrypted message: {:?}", hex::encode(alice_second_ciphertext.serialize()));
    
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
    let bob_second_reply = "It's amazing! The Kyber1024 integration provides excellent quantum resistance.";
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
    println!("Encrypted reply: {:?}", hex::encode(bob_second_ciphertext.serialize()));
    
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
    println!("Using Kyber1024 for key exchange with normal ratchet");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn benchmark_kyber_performance() -> Result<(), SignalProtocolError> {
        println!("\n=== POST-QUANTUM CRYPTOGRAPHY PERFORMANCE BENCHMARKING ===");
        
        use std::time::{Duration, Instant};
        use std::collections::HashMap;
        use std::mem;
        
        let mut csprng = rand::rng();

        // Memory and storage tracking structures
        #[derive(Debug, Clone, Default)]
        struct MemoryStats {
            key_size: usize,
            ciphertext_size: usize,
            signature_size: usize,
            bundle_size: usize,
            session_state_size: usize,
            total_storage: usize,
        }
        
        // Helper function to estimate object size in memory
        fn estimate_size<T>(obj: &T) -> usize {
            mem::size_of_val(obj)
        }
        
        // Helper function to calculate serialized size
        fn get_serialized_size(data: &[u8]) -> usize {
            data.len()
        }
        
        // Different message sizes to test
        let message_sizes = vec![
            ("Tiny", 16),       // 16 bytes
            ("Small", 256),     // 256 bytes  
            ("Medium", 4096),   // 4KB
            ("Large", 65536),   // 64KB
            ("XLarge", 1048576), // 1MB
            ("XXLarge", 104857600), // 100MB
        ];
        
        let num_iterations = 100; // Number of iterations for each test
        let num_key_pairs = 50;   // Number of different key pairs to test
        
        println!("Running {} iterations with {} different key pairs each", num_iterations, num_key_pairs);
        println!("Message sizes: {:?}", message_sizes.iter().map(|(name, size)| format!("{}: {} bytes", name, size)).collect::<Vec<_>>());
        println!("Post-quantum features: Kyber1024 KEM integration");
        
        // Storage for benchmark results
        let mut results: HashMap<String, Vec<Duration>> = HashMap::new();
        let mut memory_results: HashMap<String, Vec<MemoryStats>> = HashMap::new();
        
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
                
                // Generate Bob's signed pre-key
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
                
                // BENCHMARK: Kyber key generation
                let start = Instant::now();
                let bob_kyber_keypair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);
                let bob_kyber_prekey_id = KyberPreKeyId::from((iteration + 1) as u32);
                let bob_kyber_prekey_signature = bob_identity
                    .private_key()
                    .calculate_signature(&bob_kyber_keypair.public_key.serialize(), &mut csprng)?;
                
                let bob_kyber_prekey = KyberPreKeyRecord::new(
                    bob_kyber_prekey_id,
                    Timestamp::from_epoch_millis(0),
                    &bob_kyber_keypair,
                    &bob_kyber_prekey_signature,
                );
                let kyber_keygen_time = start.elapsed();
                results.entry(format!("{}_kyber_keygen", size_name))
                    .or_insert_with(Vec::new)
                    .push(kyber_keygen_time);
                
                // Memory analysis for Kyber key generation
                let mut kyber_memory = MemoryStats::default();
                kyber_memory.key_size = get_serialized_size(&bob_kyber_keypair.public_key.serialize());
                kyber_memory.signature_size = get_serialized_size(&bob_kyber_prekey_signature);
                kyber_memory.total_storage = kyber_memory.key_size + kyber_memory.signature_size + 
                                           estimate_size(&bob_kyber_prekey);
                
                memory_results.entry(format!("{}_kyber_keygen", size_name))
                    .or_insert_with(Vec::new)
                    .push(kyber_memory);
                
                let bob_prekey_pair = KeyPair::generate(&mut csprng);
                let bob_prekey_id = PreKeyId::from((iteration + 1) as u32);
                let bob_prekey = PreKeyRecord::new(bob_prekey_id, &bob_prekey_pair);
                
                // Store Bob's keys
                bob_store.save_signed_pre_key(bob_signed_prekey_id, &bob_signed_prekey).await?;
                bob_store.save_kyber_pre_key(bob_kyber_prekey_id, &bob_kyber_prekey).await?;
                bob_store.save_pre_key(bob_prekey_id, &bob_prekey).await?;
                
                // Create pre-key bundle WITH Kyber key (post-quantum crypto)
                let bob_prekey_bundle = PreKeyBundle::new(
                    bob_store.get_local_registration_id().await?,
                    1.into(),
                    Some((bob_prekey_id, bob_prekey.public_key()?)),
                    bob_signed_prekey_id,
                    bob_signed_prekey.public_key()?,
                    bob_signed_prekey.signature().unwrap(),
                    *bob_identity.identity_key(),
                )?
                .with_kyber_pre_key(
                    bob_kyber_prekey_id,
                    bob_kyber_prekey.public_key().unwrap(),
                    bob_kyber_prekey.signature().unwrap(),
                );
                
                // BENCHMARK 1: Pre-key bundle processing (with post-quantum)
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
                
                // Memory analysis for pre-key bundle processing
                let mut bundle_memory = MemoryStats::default();
                bundle_memory.bundle_size = estimate_size(&bob_prekey_bundle);
                bundle_memory.key_size = get_serialized_size(&bob_kyber_keypair.public_key.serialize());
                bundle_memory.signature_size = get_serialized_size(&bob_kyber_prekey_signature);
                bundle_memory.total_storage = bundle_memory.bundle_size;
                
                memory_results.entry(format!("{}_prekey_bundle_processing", size_name))
                    .or_insert_with(Vec::new)
                    .push(bundle_memory);
                
                // BENCHMARK 2: First message encryption (after prekey bundle with PQ)
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
                
                // Memory analysis for first message encryption
                let mut encrypt_memory = MemoryStats::default();
                encrypt_memory.ciphertext_size = get_serialized_size(&alice_ciphertext.serialize());
                encrypt_memory.total_storage = encrypt_memory.ciphertext_size + test_message.len();
                
                memory_results.entry(format!("{}_first_message_encrypt", size_name))
                    .or_insert_with(Vec::new)
                    .push(encrypt_memory);
                
                // BENCHMARK 3: Pre-key message decryption (with PQ)
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
                
                // Memory analysis for pre-key message decryption
                let mut decrypt_memory = MemoryStats::default();
                decrypt_memory.ciphertext_size = get_serialized_size(&alice_ciphertext.serialize());
                decrypt_memory.session_state_size = estimate_size(&bob_store.session_store);
                decrypt_memory.total_storage = decrypt_memory.ciphertext_size + bob_plaintext.len();
                
                memory_results.entry(format!("{}_prekey_message_decrypt", size_name))
                    .or_insert_with(Vec::new)
                    .push(decrypt_memory);
                
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
                
                // Memory analysis for subsequent message encryption
                let mut sub_encrypt_memory = MemoryStats::default();
                sub_encrypt_memory.ciphertext_size = get_serialized_size(&bob_reply_ciphertext.serialize());
                sub_encrypt_memory.total_storage = sub_encrypt_memory.ciphertext_size + test_message.len();
                
                memory_results.entry(format!("{}_subsequent_message_encrypt", size_name))
                    .or_insert_with(Vec::new)
                    .push(sub_encrypt_memory);
                
                // BENCHMARK 5: Normal signal message decryption (normal ratchet)
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
                
                // Memory analysis for normal signal message decryption
                let mut signal_decrypt_memory = MemoryStats::default();
                signal_decrypt_memory.ciphertext_size = get_serialized_size(&bob_reply_ciphertext.serialize());
                signal_decrypt_memory.session_state_size = estimate_size(&alice_store.session_store);
                signal_decrypt_memory.total_storage = signal_decrypt_memory.ciphertext_size + alice_received.len();
                
                memory_results.entry(format!("{}_signal_message_decrypt", size_name))
                    .or_insert_with(Vec::new)
                    .push(signal_decrypt_memory);
                
                // Verify decryption
                assert_eq!(test_message.as_bytes(), alice_received);
                
                // BENCHMARK 6: Multiple ratchet turns for performance stability
                for ratchet_turn in 0..5 {
                    // Alice encrypts (normal ratchet)
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
                    
                    // Bob decrypts (normal ratchet)
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
        println!("\n=== POST-QUANTUM PERFORMANCE ANALYSIS RESULTS ===");
        
        fn calculate_stats(times: &[Duration]) -> (Duration, Duration, Duration, Duration, Duration, f64) {
            let mut sorted_times = times.to_vec();
            sorted_times.sort();
            
            let mean = Duration::from_nanos(
                (times.iter().map(|d| d.as_nanos()).sum::<u128>() / times.len() as u128) as u64
            );
            
            // Calculate standard deviation
            let variance = times.iter()
                .map(|d| {
                    let diff = d.as_nanos() as i128 - mean.as_nanos() as i128;
                    (diff * diff) as u128
                })
                .sum::<u128>() / times.len() as u128;
            let std_dev = Duration::from_nanos((variance as f64).sqrt() as u64);
            
            // Calculate coefficient of variation (deviation percentage)
            let dev_percentage = if mean.as_nanos() > 0 {
                (std_dev.as_nanos() as f64 / mean.as_nanos() as f64) * 100.0
            } else {
                0.0
            };
            
            let median = sorted_times[times.len() / 2];
            let min = sorted_times[0];
            let max = sorted_times[times.len() - 1];
            
            (mean, median, min, max, std_dev, dev_percentage)
        }
        
        // Group results by operation type
        let operations = vec![
            "kyber_keygen",
            "prekey_bundle_processing",
            "first_message_encrypt", 
            "prekey_message_decrypt",
            "subsequent_message_encrypt",
            "signal_message_decrypt"
        ];
        
        for operation in &operations {
            println!("\n--- {} ---", operation.replace('_', " ").to_uppercase());
            println!("{:<12} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12} {:<15}", "Size", "Mean", "Median", "Min", "Max", "Std Dev", "Dev %", "Throughput");
            println!("{}", "-".repeat(105));
            
            for (size_name, message_size) in &message_sizes {
                let key = format!("{}_{}", size_name, operation);
                if let Some(times) = results.get(&key) {
                    let (mean, median, min, max, std_dev, dev_percentage) = calculate_stats(times);
                    
                    // Calculate throughput (MB/s for encryption/decryption operations)
                    let throughput = if operation.contains("encrypt") || operation.contains("decrypt") {
                        let mb_per_second = (*message_size as f64) / (1024.0 * 1024.0) / mean.as_secs_f64();
                        format!("{:.2} MB/s", mb_per_second)
                    } else {
                        "N/A".to_string()
                    };
                    
                    println!("{:<12} {:<12.2?} {:<12.2?} {:<12.2?} {:<12.2?} {:<12.2?} {:<12.1}% {:<15}", 
                             size_name, mean, median, min, max, std_dev, dev_percentage, throughput);
                }
            }
        }
        
        // Memory and Storage Analysis
        println!("\n=== POST-QUANTUM MEMORY AND STORAGE ANALYSIS ===");
        
        fn calculate_memory_stats(memories: &[MemoryStats]) -> (f64, f64, f64, f64, f64, f64, f64) {
            let key_sizes: Vec<usize> = memories.iter().map(|m| m.key_size).collect();
            let ciphertext_sizes: Vec<usize> = memories.iter().map(|m| m.ciphertext_size).collect();
            let signature_sizes: Vec<usize> = memories.iter().map(|m| m.signature_size).collect();
            let bundle_sizes: Vec<usize> = memories.iter().map(|m| m.bundle_size).collect();
            let session_sizes: Vec<usize> = memories.iter().map(|m| m.session_state_size).collect();
            let total_sizes: Vec<usize> = memories.iter().map(|m| m.total_storage).collect();
            
            let avg_key = if !key_sizes.is_empty() { key_sizes.iter().sum::<usize>() as f64 / key_sizes.len() as f64 } else { 0.0 };
            let avg_ciphertext = if !ciphertext_sizes.is_empty() { ciphertext_sizes.iter().sum::<usize>() as f64 / ciphertext_sizes.len() as f64 } else { 0.0 };
            let avg_signature = if !signature_sizes.is_empty() { signature_sizes.iter().sum::<usize>() as f64 / signature_sizes.len() as f64 } else { 0.0 };
            let avg_bundle = if !bundle_sizes.is_empty() { bundle_sizes.iter().sum::<usize>() as f64 / bundle_sizes.len() as f64 } else { 0.0 };
            let avg_session = if !session_sizes.is_empty() { session_sizes.iter().sum::<usize>() as f64 / session_sizes.len() as f64 } else { 0.0 };
            let avg_total = if !total_sizes.is_empty() { total_sizes.iter().sum::<usize>() as f64 / total_sizes.len() as f64 } else { 0.0 };
            let max_total = if !total_sizes.is_empty() { *total_sizes.iter().max().unwrap() as f64 } else { 0.0 };
            
            (avg_key, avg_ciphertext, avg_signature, avg_bundle, avg_session, avg_total, max_total)
        }
        
        fn format_bytes(bytes: f64) -> String {
            if bytes >= 1024.0 * 1024.0 {
                format!("{:.2} MB", bytes / (1024.0 * 1024.0))
            } else if bytes >= 1024.0 {
                format!("{:.2} KB", bytes / 1024.0)
            } else {
                format!("{:.0} B", bytes)
            }
        }
        
        // Display memory usage by operation
        for operation in &operations {
            println!("\n--- {} MEMORY & STORAGE USAGE ---", operation.replace('_', " ").to_uppercase());
            println!("{:<12} {:<15} {:<15} {:<15} {:<15} {:<15} {:<15} {:<15}", 
                     "Size", "Avg Key", "Avg Cipher", "Avg Signature", "Avg Bundle", "Avg Session", "Avg Total", "Max Total");
            println!("{}", "-".repeat(120));
            
            for (size_name, _) in &message_sizes {
                let key = format!("{}_{}", size_name, operation);
                if let Some(memories) = memory_results.get(&key) {
                    let (avg_key, avg_ciphertext, avg_signature, avg_bundle, avg_session, avg_total, max_total) = 
                        calculate_memory_stats(memories);
                    
                    println!("{:<12} {:<15} {:<15} {:<15} {:<15} {:<15} {:<15} {:<15}", 
                             size_name, 
                             format_bytes(avg_key),
                             format_bytes(avg_ciphertext),
                             format_bytes(avg_signature),
                             format_bytes(avg_bundle),
                             format_bytes(avg_session),
                             format_bytes(avg_total),
                             format_bytes(max_total));
                }
            }
        }
        
        // Calculate and display storage overhead analysis
        println!("\n--- STORAGE OVERHEAD ANALYSIS ---");
        println!("{:<12} {:<15} {:<15} {:<15} {:<15}", "Message Size", "Plaintext", "Ciphertext", "Overhead", "Overhead %");
        println!("{}", "-".repeat(75));
        
        for (size_name, message_size) in &message_sizes {
            // Get average ciphertext size from first message encrypt
            if let Some(memories) = memory_results.get(&format!("{}_first_message_encrypt", size_name)) {
                let (_, avg_ciphertext, _, _, _, _, _) = calculate_memory_stats(memories);
                let overhead = avg_ciphertext - (*message_size as f64);
                let overhead_percent = (overhead / (*message_size as f64)) * 100.0;
                
                println!("{:<12} {:<15} {:<15} {:<15} {:<15.1}%", 
                         size_name,
                         format_bytes(*message_size as f64),
                         format_bytes(avg_ciphertext),
                         format_bytes(overhead),
                         overhead_percent);
            }
        }
        
        // Display key size analysis
        println!("\n--- POST-QUANTUM KEY SIZE ANALYSIS ---");
        if let Some(memories) = memory_results.get("Tiny_kyber_keygen") {
            let (avg_key, _, avg_signature, _, _, _, _) = calculate_memory_stats(memories);
            println!("• Kyber1024 Public Key Size: {}", format_bytes(avg_key));
            println!("• Kyber1024 Signature Size: {}", format_bytes(avg_signature));
            println!("• Total Kyber Key Material: {}", format_bytes(avg_key + avg_signature));
        }
        
        // Session state memory analysis
        println!("\n--- SESSION STATE MEMORY USAGE ---");
        for operation in &["prekey_message_decrypt", "signal_message_decrypt"] {
            if let Some(memories) = memory_results.get(&format!("Tiny_{}", operation)) {
                let (_, _, _, _, avg_session, _, _) = calculate_memory_stats(memories);
                println!("• {} Session State: {}", 
                         operation.replace('_', " ").replace("message ", "").to_uppercase(),
                         format_bytes(avg_session));
            }
        }
        
        // Compare memory efficiency across message sizes
        println!("\n--- MEMORY EFFICIENCY ANALYSIS ---");
        println!("Efficiency = Message Size / Total Storage Used");
        println!("{:<12} {:<15} {:<15} {:<15}", "Message Size", "Encrypt Eff.", "Decrypt Eff.", "Avg Efficiency");
        println!("{}", "-".repeat(60));
        
        for (size_name, message_size) in &message_sizes {
            let mut encrypt_eff = 0.0;
            let mut decrypt_eff = 0.0;
            
            if let Some(memories) = memory_results.get(&format!("{}_first_message_encrypt", size_name)) {
                let (_, _, _, _, _, avg_total, _) = calculate_memory_stats(memories);
                if avg_total > 0.0 {
                    encrypt_eff = (*message_size as f64) / avg_total;
                }
            }
            
            if let Some(memories) = memory_results.get(&format!("{}_signal_message_decrypt", size_name)) {
                let (_, _, _, _, _, avg_total, _) = calculate_memory_stats(memories);
                if avg_total > 0.0 {
                    decrypt_eff = (*message_size as f64) / avg_total;
                }
            }
            
            let avg_efficiency = if encrypt_eff > 0.0 && decrypt_eff > 0.0 {
                (encrypt_eff + decrypt_eff) / 2.0
            } else if encrypt_eff > 0.0 {
                encrypt_eff
            } else {
                decrypt_eff
            };
            
            println!("{:<12} {:<15.3} {:<15.3} {:<15.3}", 
                     size_name, encrypt_eff, decrypt_eff, avg_efficiency);
        }
        
        // Display ratchet performance with normal ratchet
        println!("\n--- RATCHET TURN PERFORMANCE (Normal Ratchet with Kyber KEM) ---");
        for ratchet_turn in 0..5 {
            println!("\n  Ratchet Turn {} (Encrypt/Decrypt with Normal Ratchet):", ratchet_turn);
            println!("  {:<12} {:<15} {:<15}", "Size", "Encrypt", "Decrypt");
            println!("  {}", "-".repeat(45));
            
            for (size_name, _) in &message_sizes {
                let encrypt_key = format!("{}_ratchet_turn_{}_encrypt", size_name, ratchet_turn);
                let decrypt_key = format!("{}_ratchet_turn_{}_decrypt", size_name, ratchet_turn);
                
                if let (Some(encrypt_times), Some(decrypt_times)) = (results.get(&encrypt_key), results.get(&decrypt_key)) {
                    let (encrypt_mean, _, _, _, _, _) = calculate_stats(encrypt_times);
                    let (decrypt_mean, _, _, _, _, _) = calculate_stats(decrypt_times);
                    
                    println!("  {:<12} {:<15.2?} {:<15.2?}", size_name, encrypt_mean, decrypt_mean);
                }
            }
        }
        
        // Performance insights specific to post-quantum cryptography
        println!("\n=== POST-QUANTUM CRYPTOGRAPHY PERFORMANCE INSIGHTS ===");
        
        // Kyber key generation overhead
        for (size_name, _) in &message_sizes {
            if let Some(kyber_times) = results.get(&format!("{}_kyber_keygen", size_name)) {
                let (kyber_mean, _, _, _, _, _) = calculate_stats(kyber_times);
                println!("• Kyber1024 key generation takes {:.2?} on average", kyber_mean);
                break; // Only need to report this once
            }
        }
        
        // Compare prekey vs normal operations with PQ overhead
        for (size_name, _) in &message_sizes {
            if let (Some(prekey_times), Some(signal_times)) = (
                results.get(&format!("{}_prekey_message_decrypt", size_name)),
                results.get(&format!("{}_signal_message_decrypt", size_name))
            ) {
                let (prekey_mean, _, _, _, _, _) = calculate_stats(prekey_times);
                let (signal_mean, _, _, _, _, _) = calculate_stats(signal_times);
                let overhead = (prekey_mean.as_nanos() as f64 / signal_mean.as_nanos() as f64) - 1.0;
                
                println!("• {} messages: PQ pre-key decryption is {:.1}% slower than PQ signal decryption", 
                         size_name, overhead * 100.0);
            }
        }
        
        // Encryption vs decryption comparison with PQ
        for (size_name, _) in &message_sizes {
            if let (Some(encrypt_times), Some(decrypt_times)) = (
                results.get(&format!("{}_subsequent_message_encrypt", size_name)),
                results.get(&format!("{}_signal_message_decrypt", size_name))
            ) {
                let (encrypt_mean, _, _, _, _, _) = calculate_stats(encrypt_times);
                let (decrypt_mean, _, _, _, _, _) = calculate_stats(decrypt_times);
                let ratio = encrypt_mean.as_nanos() as f64 / decrypt_mean.as_nanos() as f64;
                
                println!("• {} messages: PQ encryption is {:.1}x {} than PQ decryption", 
                         size_name, ratio.abs(), if ratio > 1.0 { "slower" } else { "faster" });
            }
        }
        
        // Bundle processing cost with PQ
        if let Some(bundle_times) = results.get("Tiny_prekey_bundle_processing") {
            let (bundle_mean, _, _, _, _, _) = calculate_stats(bundle_times);
            println!("• PQ pre-key bundle processing takes {:.2?} on average", bundle_mean);
        }
        
        // Memory-specific insights
        println!("\n=== MEMORY AND STORAGE INSIGHTS ===");
        
        // Calculate total memory overhead for different operations
        for (size_name, message_size) in message_sizes.iter().take(1) { // Just show for one size to avoid repetition
            if let Some(memories) = memory_results.get(&format!("{}_kyber_keygen", size_name)) {
                let (avg_key, _, avg_signature, _, _, _, _) = calculate_memory_stats(memories);
                println!("• Kyber1024 key generation requires {} key + {} signature = {} total", 
                         format_bytes(avg_key), format_bytes(avg_signature), format_bytes(avg_key + avg_signature));
            }
            
            if let Some(memories) = memory_results.get(&format!("{}_first_message_encrypt", size_name)) {
                let (_, avg_ciphertext, _, _, _, _, _) = calculate_memory_stats(memories);
                let overhead = avg_ciphertext - (*message_size as f64);
                println!("• Message encryption adds {} overhead to {} plaintext ({:.1}% increase)", 
                         format_bytes(overhead), format_bytes(*message_size as f64), 
                         (overhead / (*message_size as f64)) * 100.0);
            }
        }
        
        // Calculate memory efficiency across all message sizes
        let mut total_efficiency = 0.0;
        let mut efficiency_count = 0;
        for (size_name, message_size) in &message_sizes {
            if let Some(memories) = memory_results.get(&format!("{}_first_message_encrypt", size_name)) {
                let (_, _, _, _, _, avg_total, _) = calculate_memory_stats(memories);
                if avg_total > 0.0 {
                    let efficiency = (*message_size as f64) / avg_total;
                    total_efficiency += efficiency;
                    efficiency_count += 1;
                }
            }
        }
        
        if efficiency_count > 0 {
            let avg_efficiency = total_efficiency / efficiency_count as f64;
            println!("• Average memory efficiency across all message sizes: {:.3} (higher is better)", avg_efficiency);
        }
        
        // Memory usage insights
        println!("\n🔐 Post-Quantum Cryptography Benchmarking completed!");
        println!("Total operations benchmarked: {}", results.len());
        println!("Total measurements taken: {}", results.values().map(|v| v.len()).sum::<usize>());
        println!("Total memory measurements: {}", memory_results.values().map(|v| v.len()).sum::<usize>());
        println!("Quantum-resistant security level: NIST Level 5 (Kyber1024)");
        
        Ok(())
    }
}