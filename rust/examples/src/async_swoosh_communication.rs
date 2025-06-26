use libsignal_protocol::*;
use libsignal_protocol::process_swoosh_prekey_bundle;
use pswoosh::keys::SwooshKeyPair;
use rand::{rng, RngCore};
use std::time::{SystemTime, Duration};
use tokio::time::sleep;

fn main() -> Result<(), SignalProtocolError> {
    use std::thread;
    
    // Create a thread with larger stack to run the async main
    let handle = thread::Builder::new()
        .stack_size(100 * 1024 * 1024) // 100MB stack for async operations
        .spawn(|| {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async_main())
        })
        .unwrap();
    
    handle.join().unwrap()
}

async fn async_main() -> Result<(), SignalProtocolError> {
    println!("=== MULTIPLE MESSAGES SWOOSH COMMUNICATION EXAMPLE ===");
    println!("Testing sending multiple messages before decryption with post-quantum ratcheting");
    
    // Initialize stores and establish initial session
    let (mut alice_store, mut bob_store, alice_address, bob_address) = setup_initial_session().await?;
    let mut csprng = rng();
    
    println!("\n=== PHASE 1: ALICE SENDS MULTIPLE MESSAGES ===");
    println!("Alice sends 3 messages in sequence before Bob decrypts any");
    
    // Alice sends multiple messages in sequence
    let alice_messages = vec![
        "First message from Alice",
        "Second message from Alice", 
        "Third message from Alice"
    ];
    
    let mut alice_ciphertexts = Vec::new();
    
    for (i, message) in alice_messages.iter().enumerate() {
        let ciphertext = message_encrypt_swoosh(
            message.as_bytes(),
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
            &mut csprng,
        ).await?;
        
        alice_ciphertexts.push(ciphertext);
        println!("✓ Alice encrypted message #{}: {}", i + 1, message);
        
        // Small delay to simulate real-world timing
        sleep(Duration::from_millis(50)).await;
    }
    
    println!("\n=== PHASE 2: BOB DECRYPTS ALL MESSAGES ===");
    println!("Bob now decrypts all 3 messages in order");
    
    // Bob decrypts all messages
    for (i, ciphertext) in alice_ciphertexts.iter().enumerate() {
        let decrypted = match ciphertext {
            CiphertextMessage::SignalMessage(signal_msg) => {
                message_decrypt_signal(
                    signal_msg,
                    &alice_address,
                    &mut bob_store.session_store,
                    &mut bob_store.identity_store,
                    &mut csprng,
                ).await?
            },
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
            _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Unexpected message type")),
        };
        
        let decrypted_text = String::from_utf8(decrypted).expect("Valid UTF-8");
        println!("✓ Bob decrypted message #{}: {}", i + 1, decrypted_text);
        assert_eq!(decrypted_text, alice_messages[i], "Message should decrypt correctly");
        
        // Processing delay
        sleep(Duration::from_millis(30)).await;
    }
    
    println!("\n=== PHASE 3: BOB SENDS MULTIPLE MESSAGES ===");
    println!("Now Bob sends multiple messages before Alice decrypts");
    
    // Bob sends multiple messages in sequence
    let bob_messages = vec![
        "First reply from Bob",
        "Second reply from Bob",
        "Third reply from Bob",
        "Fourth reply from Bob"
    ];
    
    let mut bob_ciphertexts = Vec::new();
    
    for (i, message) in bob_messages.iter().enumerate() {
        let ciphertext = message_encrypt_swoosh(
            message.as_bytes(),
            &alice_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            SystemTime::now(),
            &mut csprng,
        ).await?;
        
        bob_ciphertexts.push(ciphertext);
        println!("✓ Bob encrypted message #{}: {}", i + 1, message);
        
        // Varying delays to simulate network conditions
        let delay = match i {
            0 => 25,
            1 => 75,
            2 => 40,
            _ => 60,
        };
        sleep(Duration::from_millis(delay)).await;
    }
    
    println!("\n=== PHASE 4: ALICE DECRYPTS ALL BOB'S MESSAGES ===");
    println!("Alice decrypts all of Bob's messages");
    
    // Alice decrypts all of Bob's messages
    for (i, ciphertext) in bob_ciphertexts.iter().enumerate() {
        let decrypted = match ciphertext {
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
        
        let decrypted_text = String::from_utf8(decrypted).expect("Valid UTF-8");
        println!("✓ Alice decrypted message #{}: {}", i + 1, decrypted_text);
        assert_eq!(decrypted_text, bob_messages[i], "Message should decrypt correctly");
        
        // Processing delay
        sleep(Duration::from_millis(35)).await;
    }
    
    println!("\n=== PHASE 5: OUT-OF-ORDER DECRYPTION TEST ===");
    println!("Testing out-of-order message decryption");
    
    // Alice sends more messages
    let more_alice_messages = vec![
        "Message A1 from Alice",
        "Message A2 from Alice", 
        "Message A3 from Alice",
        "Message A4 from Alice"
    ];
    
    let mut more_alice_ciphertexts = Vec::new();
    
    for (i, message) in more_alice_messages.iter().enumerate() {
        let ciphertext = message_encrypt_swoosh(
            message.as_bytes(),
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
            &mut csprng,
        ).await?;
        
        more_alice_ciphertexts.push(ciphertext);
        println!("✓ Alice encrypted out-of-order test message #{}: {}", i + 1, message);
        sleep(Duration::from_millis(20)).await;
    }
    
    // Bob decrypts in different order: 1st, 3rd, 2nd, 4th
    let decrypt_order = [0, 2, 1, 3];
    println!("Bob decrypting in order: 1st, 3rd, 2nd, 4th");
    
    for &msg_idx in &decrypt_order {
        let ciphertext = &more_alice_ciphertexts[msg_idx];
        let decrypted = match ciphertext {
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
        
        let decrypted_text = String::from_utf8(decrypted).expect("Valid UTF-8");
        println!("✓ Bob decrypted message #{} out-of-order: {}", msg_idx + 1, decrypted_text);
        assert_eq!(decrypted_text, more_alice_messages[msg_idx], "Out-of-order message should decrypt correctly");
        
        sleep(Duration::from_millis(25)).await;
    }
    
    println!("\n=== PHASE 6: RAPID SUCCESSION TEST ===");
    println!("Testing rapid message sending with minimal delays");
    
    let rapid_messages = vec![
        "Rapid 1", "Rapid 2", "Rapid 3", "Rapid 4", "Rapid 5",
        "Rapid 6", "Rapid 7", "Rapid 8", "Rapid 9", "Rapid 10"
    ];
    
    let mut rapid_ciphertexts = Vec::new();
    
    // Alice sends messages rapidly
    for (i, message) in rapid_messages.iter().enumerate() {
        let ciphertext = message_encrypt_swoosh(
            message.as_bytes(),
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
            &mut csprng,
        ).await?;
        
        rapid_ciphertexts.push(ciphertext);
        if i % 3 == 0 {
            println!("✓ Alice sent rapid messages {}-{}", i + 1, std::cmp::min(i + 3, rapid_messages.len()));
        }
        
        // Very short delay
        sleep(Duration::from_millis(5)).await;
    }
    
    // Bob decrypts all rapid messages
    let mut successful_decrypts = 0;
    for (i, ciphertext) in rapid_ciphertexts.iter().enumerate() {
        let decrypted = match ciphertext {
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
        
        let decrypted_text = String::from_utf8(decrypted).expect("Valid UTF-8");
        if decrypted_text == rapid_messages[i] {
            successful_decrypts += 1;
        }
        
        // Minimal processing delay
        sleep(Duration::from_millis(2)).await;
    }
    
    println!("✓ Bob successfully decrypted {}/{} rapid messages", successful_decrypts, rapid_messages.len());
    
    println!("\n=== MULTIPLE MESSAGES COMMUNICATION COMPLETE ===");
    println!("🎉 Successfully tested:");
    println!("  • Multiple messages sent before decryption");
    println!("  • Bidirectional multiple message exchange");
    println!("  • Out-of-order message decryption");
    println!("  • Rapid succession message handling");
    println!("  • Swoosh post-quantum ratchet consistency");
    
    let total_messages = alice_messages.len() + bob_messages.len() + more_alice_messages.len() + rapid_messages.len();
    println!("  • Total messages processed: {}", total_messages);
    println!("  • All using Swoosh post-quantum cryptography ✨");
    println!("  • Demonstrates real-world async messaging patterns");
    
    Ok(())
}

async fn setup_initial_session() -> Result<(InMemSignalProtocolStore, InMemSignalProtocolStore, ProtocolAddress, ProtocolAddress), SignalProtocolError> {
    let mut csprng = rng();
    
    println!("Setting up initial Swoosh session...");
    
    // Create addresses
    let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14151112222".to_owned(), 1.into());
    
    // Generate identity key pairs
    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);
    
    // Create stores
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
    
    // Generate Bob's Swoosh pre-key
    let bob_swoosh_key_pair = SwooshKeyPair::generate(false);
    let bob_swoosh_prekey_id = SwooshPreKeyId::from(1u32);
    let bob_swoosh_prekey_signature = bob_identity
        .private_key()
        .calculate_signature(&bob_swoosh_key_pair.public_key.serialize(), &mut csprng)?;

    let bob_swoosh_prekey = SwooshPreKeyRecord::new(
        bob_swoosh_prekey_id,
        Timestamp::from_epoch_millis(0),
        &bob_swoosh_key_pair,
        &bob_swoosh_prekey_signature,
    );
    
    // Store Bob's pre-keys
    bob_store.save_signed_pre_key(bob_signed_prekey_id, &bob_signed_prekey).await?;
    bob_store.save_swoosh_pre_key(bob_swoosh_prekey_id, &bob_swoosh_prekey).await?;
    
    // Create pre-key bundle with Swoosh
    let bob_prekey_bundle = PreKeyBundle::new(
        bob_store.get_local_registration_id().await?,
        1.into(),
        None,
        bob_signed_prekey_id,
        bob_signed_prekey.public_key()?,
        bob_signed_prekey.signature().unwrap(),
        *bob_identity.identity_key(),
    )?
    .with_swoosh_pre_key(
        bob_swoosh_prekey_id,
        bob_swoosh_prekey.public_key()?,
        bob_swoosh_prekey.signature().unwrap()
    );
    
    // Alice processes pre-key bundle to establish session
    process_swoosh_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_prekey_bundle,
        SystemTime::now(),
        &mut csprng,
        UsePQRatchet::No,
    ).await?;
    
    // Send initial message to complete session establishment
    let initial_message = "Initial session establishment message";
    let initial_ciphertext = message_encrypt_swoosh(
        initial_message.as_bytes(),
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut csprng,
    ).await?;
    
    // Bob decrypts to complete his side of session establishment
    match &initial_ciphertext {
        CiphertextMessage::PreKeySignalMessage(prekey_msg) => {
            let _decrypted = message_decrypt_prekey(
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
            ).await?;
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected PreKeySignalMessage")),
    }
    
    println!("✓ Initial Swoosh session established between Alice and Bob");
    
    Ok((alice_store, bob_store, alice_address, bob_address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_multiple_message_sequence() -> Result<(), SignalProtocolError> {
        println!("\n=== TESTING MULTIPLE MESSAGE SEQUENCE ===");
        
        let (mut alice_store, mut bob_store, alice_address, bob_address) = setup_initial_session().await?;
        let mut csprng = rng();
        
        // Alice sends multiple messages
        let messages = vec!["Test message 1", "Test message 2", "Test message 3"];
        let mut ciphertexts = Vec::new();
        
        for message in &messages {
            let ciphertext = message_encrypt_swoosh(
                message.as_bytes(),
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                SystemTime::now(),
                &mut csprng,
            ).await?;
            ciphertexts.push(ciphertext);
        }
        
        // Bob decrypts all messages
        for (i, ciphertext) in ciphertexts.iter().enumerate() {
            let decrypted = match ciphertext {
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
            
            let decrypted_text = String::from_utf8(decrypted).expect("Valid UTF-8");
            assert_eq!(decrypted_text, messages[i], "Message should decrypt correctly");
        }
        
        println!("✓ Multiple message sequence test passed");
        Ok(())
    }
    
    #[tokio::test]
    async fn test_out_of_order_decryption() -> Result<(), SignalProtocolError> {
        println!("\n=== TESTING OUT-OF-ORDER DECRYPTION ===");
        
        let (mut alice_store, mut bob_store, alice_address, bob_address) = setup_initial_session().await?;
        let mut csprng = rng();
        
        // Alice sends multiple messages
        let messages = vec!["Message A", "Message B", "Message C", "Message D"];
        let mut ciphertexts = Vec::new();
        
        for message in &messages {
            let ciphertext = message_encrypt_swoosh(
                message.as_bytes(),
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                SystemTime::now(),
                &mut csprng,
            ).await?;
            ciphertexts.push(ciphertext);
        }
        
        // Bob decrypts in different order: 1st, 3rd, 2nd, 4th
        let decrypt_order = [0, 2, 1, 3];
        
        for &msg_idx in &decrypt_order {
            let ciphertext = &ciphertexts[msg_idx];
            let decrypted = match ciphertext {
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
            
            let decrypted_text = String::from_utf8(decrypted).expect("Valid UTF-8");
            assert_eq!(decrypted_text, messages[msg_idx], "Out-of-order message should decrypt correctly");
        }
        
        println!("✓ Out-of-order decryption test passed");
        Ok(())
    }
    
    #[tokio::test]
    async fn test_bidirectional_multiple_messages() -> Result<(), SignalProtocolError> {
        println!("\n=== TESTING BIDIRECTIONAL MULTIPLE MESSAGES ===");
        
        let (mut alice_store, mut bob_store, alice_address, bob_address) = setup_initial_session().await?;
        let mut csprng = rng();
        
        // Alice sends messages
        let alice_messages = vec!["Alice 1", "Alice 2"];
        let mut alice_ciphertexts = Vec::new();
        
        for message in &alice_messages {
            let ciphertext = message_encrypt_swoosh(
                message.as_bytes(),
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                SystemTime::now(),
                &mut csprng,
            ).await?;
            alice_ciphertexts.push(ciphertext);
        }
        
        // Bob sends messages
        let bob_messages = vec!["Bob 1", "Bob 2", "Bob 3"];
        let mut bob_ciphertexts = Vec::new();
        
        for message in &bob_messages {
            let ciphertext = message_encrypt_swoosh(
                message.as_bytes(),
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                SystemTime::now(),
                &mut csprng,
            ).await?;
            bob_ciphertexts.push(ciphertext);
        }
        
        // Bob decrypts Alice's messages
        for (i, ciphertext) in alice_ciphertexts.iter().enumerate() {
            let decrypted = match ciphertext {
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
            
            let decrypted_text = String::from_utf8(decrypted).expect("Valid UTF-8");
            assert_eq!(decrypted_text, alice_messages[i], "Alice's message should decrypt correctly");
        }
        
        // Alice decrypts Bob's messages
        for (i, ciphertext) in bob_ciphertexts.iter().enumerate() {
            let decrypted = match ciphertext {
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
            
            let decrypted_text = String::from_utf8(decrypted).expect("Valid UTF-8");
            assert_eq!(decrypted_text, bob_messages[i], "Bob's message should decrypt correctly");
        }
        
        println!("✓ Bidirectional multiple messages test passed");
        Ok(())
    }
    
    #[tokio::test]
    async fn test_timeout_resilience() -> Result<(), SignalProtocolError> {
        println!("\n=== TESTING TIMEOUT RESILIENCE ===");
        
        let (mut alice_store, _bob_store, _alice_address, bob_address) = setup_initial_session().await?;
        let mut csprng = rng();
        
        // Test that operations complete within reasonable time
        let encryption_task = async {
            message_encrypt_swoosh(
                b"Timeout test message",
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                SystemTime::now(),
                &mut csprng,
            ).await
        };
        
        let result = timeout(Duration::from_secs(5), encryption_task).await;
        assert!(result.is_ok(), "Encryption should complete within timeout");
        assert!(result.unwrap().is_ok(), "Encryption should succeed");
        
        println!("✓ Timeout resilience test passed");
        Ok(())
    }
}
