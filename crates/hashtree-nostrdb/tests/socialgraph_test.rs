use nostrdb::{Config, Ndb, Transaction};
use std::fs;

fn cleanup_db(path: &str) {
    let _ = fs::remove_dir_all(path);
}

fn hex_decode(hex: &str) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    result
}

fn create_contact_list(_ndb: &Ndb, author: &[u8; 32], follows: &[[u8; 32]], timestamp: u64) -> String {
    let mut tags = String::new();
    for pk in follows {
        let hex = hex::encode(pk);
        tags.push_str(&format!(",[\"p\",\"{}\"]", hex));
    }

    // Use timestamp as a unique event ID to avoid deduplication
    let event_id = format!("{:064x}", timestamp);

    format!(
        r#"{{"id":"{}","pubkey":"{}","created_at":{},"kind":3,"tags":[{}],"content":"","sig":"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}}"#,
        event_id,
        hex::encode(author),
        timestamp,
        &tags[1..] // skip leading comma
    )
}

fn create_mute_list(_ndb: &Ndb, author: &[u8; 32], mutes: &[[u8; 32]], timestamp: u64) -> String {
    let mut tags = String::new();
    for pk in mutes {
        let hex = hex::encode(pk);
        tags.push_str(&format!(",[\"p\",\"{}\"]", hex));
    }

    // Use timestamp as a unique event ID to avoid deduplication
    let event_id = format!("{:064x}", timestamp);

    format!(
        r#"{{"id":"{}","pubkey":"{}","created_at":{},"kind":10000,"tags":[{}],"content":"","sig":"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}}"#,
        event_id,
        hex::encode(author),
        timestamp,
        &tags[1..] // skip leading comma
    )
}

#[test]
fn test_follow_distance() {
    let db = "target/testdbs/socialgraph_distance";
    cleanup_db(db);

    // Create pubkeys - root must be zero pubkey (hardcoded in nostrdb init)
    let root_pk = [0u8; 32];
    let alice_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000002");
    let bob_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000003");
    let carol_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000004");

    // Initialize with root - skip validation since we're using fake sigs
    let cfg = Config::new().skip_validation(true);
    let ndb = Ndb::new(db, &cfg).expect("ndb init failed");

    // Root follows Alice
    let json = create_contact_list(&ndb, &root_pk, &[alice_pk], 1234567890);
    ndb.process_event(&json).expect("process failed");

    // Alice follows Bob
    let json = create_contact_list(&ndb, &alice_pk, &[bob_pk], 1234567891);
    ndb.process_event(&json).expect("process failed");

    // Wait for processing
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Query distances
    let txn = Transaction::new(&ndb).expect("txn failed");

    let root_dist = nostrdb::socialgraph::get_follow_distance(&txn, &ndb, &root_pk);
    let alice_dist = nostrdb::socialgraph::get_follow_distance(&txn, &ndb, &alice_pk);
    let bob_dist = nostrdb::socialgraph::get_follow_distance(&txn, &ndb, &bob_pk);
    let carol_dist = nostrdb::socialgraph::get_follow_distance(&txn, &ndb, &carol_pk);

    println!("Root distance: {}", root_dist);
    println!("Alice distance: {}", alice_dist);
    println!("Bob distance: {}", bob_dist);
    println!("Carol distance: {}", carol_dist);

    // Root should be 0, Alice 1, Bob 2, Carol not in graph (1000)
    assert_eq!(root_dist, 0, "Root should have distance 0");
    assert_eq!(alice_dist, 1, "Alice should have distance 1");
    assert_eq!(bob_dist, 2, "Bob should have distance 2");
    assert_eq!(carol_dist, 1000, "Carol should not be in graph");

    drop(txn);
    cleanup_db(db);
}

#[test]
fn test_is_following() {
    let db = "target/testdbs/socialgraph_following";
    cleanup_db(db);

    let root_pk = [0u8; 32];
    let alice_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000002");
    let bob_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000003");

    let cfg = Config::new().skip_validation(true);
    let ndb = Ndb::new(db, &cfg).expect("ndb init failed");

    // Root follows Alice
    let json = create_contact_list(&ndb, &root_pk, &[alice_pk], 1234567890);
    ndb.process_event(&json).expect("process failed");

    std::thread::sleep(std::time::Duration::from_millis(500));

    let txn = Transaction::new(&ndb).expect("txn failed");

    assert!(nostrdb::socialgraph::is_following(&txn, &ndb, &root_pk, &alice_pk));
    assert!(!nostrdb::socialgraph::is_following(&txn, &ndb, &root_pk, &bob_pk));
    assert!(!nostrdb::socialgraph::is_following(&txn, &ndb, &alice_pk, &root_pk));

    drop(txn);
    cleanup_db(db);
}

#[test]
fn test_get_followed() {
    let db = "target/testdbs/socialgraph_followed";
    cleanup_db(db);

    let root_pk = [0u8; 32];
    let alice_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000002");
    let bob_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000003");

    let cfg = Config::new().skip_validation(true);
    let ndb = Ndb::new(db, &cfg).expect("ndb init failed");

    // Root follows Alice and Bob
    let json = create_contact_list(&ndb, &root_pk, &[alice_pk, bob_pk], 1234567890);
    ndb.process_event(&json).expect("process failed");

    std::thread::sleep(std::time::Duration::from_millis(500));

    let txn = Transaction::new(&ndb).expect("txn failed");

    let followed = nostrdb::socialgraph::get_followed(&txn, &ndb, &root_pk, 10);
    assert_eq!(followed.len(), 2);
    assert!(followed.contains(&alice_pk));
    assert!(followed.contains(&bob_pk));

    drop(txn);
    cleanup_db(db);
}

#[test]
fn test_follower_count() {
    let db = "target/testdbs/socialgraph_count";
    cleanup_db(db);

    let root_pk = [0u8; 32];
    let alice_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000002");
    let bob_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000003");

    let cfg = Config::new().skip_validation(true);
    let ndb = Ndb::new(db, &cfg).expect("ndb init failed");

    // Root and Bob both follow Alice
    let json1 = create_contact_list(&ndb, &root_pk, &[alice_pk], 1234567890);
    ndb.process_event(&json1).expect("process failed");

    let json2 = create_contact_list(&ndb, &bob_pk, &[alice_pk], 1234567891);
    ndb.process_event(&json2).expect("process failed");

    std::thread::sleep(std::time::Duration::from_millis(500));

    let txn = Transaction::new(&ndb).expect("txn failed");

    let count = nostrdb::socialgraph::follower_count(&txn, &ndb, &alice_pk);
    assert_eq!(count, 2, "Alice should have 2 followers");

    drop(txn);
    cleanup_db(db);
}

#[test]
fn test_is_muting() {
    let db = "target/testdbs/socialgraph_muting";
    cleanup_db(db);

    let root_pk = [0u8; 32];
    let alice_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000002");
    let bob_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000003");

    let cfg = Config::new().skip_validation(true);
    let ndb = Ndb::new(db, &cfg).expect("ndb init failed");

    // Alice mutes Bob
    let json = create_mute_list(&ndb, &alice_pk, &[bob_pk], 1234567890);
    ndb.process_event(&json).expect("process failed");

    std::thread::sleep(std::time::Duration::from_millis(500));

    let txn = Transaction::new(&ndb).expect("txn failed");

    assert!(nostrdb::socialgraph::is_muting(&txn, &ndb, &alice_pk, &bob_pk));
    assert!(!nostrdb::socialgraph::is_muting(&txn, &ndb, &alice_pk, &root_pk));
    assert!(!nostrdb::socialgraph::is_muting(&txn, &ndb, &bob_pk, &alice_pk));

    drop(txn);
    cleanup_db(db);
}

#[test]
fn test_get_muted() {
    let db = "target/testdbs/socialgraph_get_muted";
    cleanup_db(db);

    let root_pk = [0u8; 32];
    let alice_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000002");
    let bob_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000003");

    let cfg = Config::new().skip_validation(true);
    let ndb = Ndb::new(db, &cfg).expect("ndb init failed");

    // Root mutes Alice and Bob
    let json = create_mute_list(&ndb, &root_pk, &[alice_pk, bob_pk], 1234567890);
    ndb.process_event(&json).expect("process failed");

    std::thread::sleep(std::time::Duration::from_millis(500));

    let txn = Transaction::new(&ndb).expect("txn failed");

    let muted = nostrdb::socialgraph::get_muted(&txn, &ndb, &root_pk, 10);
    assert_eq!(muted.len(), 2);
    assert!(muted.contains(&alice_pk));
    assert!(muted.contains(&bob_pk));

    drop(txn);
    cleanup_db(db);
}

#[test]
fn test_get_muters() {
    let db = "target/testdbs/socialgraph_get_muters";
    cleanup_db(db);

    let root_pk = [0u8; 32];
    let alice_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000002");
    let bob_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000003");

    let cfg = Config::new().skip_validation(true);
    let ndb = Ndb::new(db, &cfg).expect("ndb init failed");

    // Root and Alice both mute Bob
    let json1 = create_mute_list(&ndb, &root_pk, &[bob_pk], 1234567890);
    ndb.process_event(&json1).expect("process failed");

    let json2 = create_mute_list(&ndb, &alice_pk, &[bob_pk], 1234567891);
    ndb.process_event(&json2).expect("process failed");

    std::thread::sleep(std::time::Duration::from_millis(500));

    let txn = Transaction::new(&ndb).expect("txn failed");

    let muters = nostrdb::socialgraph::get_muters(&txn, &ndb, &bob_pk, 10);
    assert_eq!(muters.len(), 2, "Bob should be muted by 2 users");
    assert!(muters.contains(&root_pk));
    assert!(muters.contains(&alice_pk));

    drop(txn);
    cleanup_db(db);
}

#[test]
fn test_mute_list_update() {
    let db = "target/testdbs/socialgraph_mute_update";
    cleanup_db(db);

    let alice_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000002");
    let bob_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000003");
    let charlie_pk = hex_decode("0000000000000000000000000000000000000000000000000000000000000004");

    let cfg = Config::new().skip_validation(true);
    let ndb = Ndb::new(db, &cfg).expect("ndb init failed");

    // Alice mutes Bob and Charlie
    let json1 = create_mute_list(&ndb, &alice_pk, &[bob_pk, charlie_pk], 1234567890);
    ndb.process_event(&json1).expect("process failed");
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Alice updates to only mute Charlie (unmutes Bob)
    let json2 = create_mute_list(&ndb, &alice_pk, &[charlie_pk], 1234567900);
    ndb.process_event(&json2).expect("process failed");
    std::thread::sleep(std::time::Duration::from_millis(200));

    let txn = Transaction::new(&ndb).expect("txn failed");

    // Alice should no longer mute Bob
    assert!(!nostrdb::socialgraph::is_muting(&txn, &ndb, &alice_pk, &bob_pk));

    // Alice should still mute Charlie
    assert!(nostrdb::socialgraph::is_muting(&txn, &ndb, &alice_pk, &charlie_pk));

    // Bob should have 0 muters now
    let bob_muters = nostrdb::socialgraph::get_muters(&txn, &ndb, &bob_pk, 10);
    assert_eq!(bob_muters.len(), 0);

    // Charlie should have 1 muter (Alice)
    let charlie_muters = nostrdb::socialgraph::get_muters(&txn, &ndb, &charlie_pk, 10);
    assert_eq!(charlie_muters.len(), 1);
    assert!(charlie_muters.contains(&alice_pk));

    drop(txn);
    cleanup_db(db);
}
