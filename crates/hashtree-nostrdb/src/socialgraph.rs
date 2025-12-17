use crate::{bindings, Ndb, Transaction};

/// Get follow distance from the root user (configured at nostrdb init)
///
/// Returns the distance from the root user:
/// - 0: root user
/// - 1: followed by root
/// - 2: followed by someone root follows
/// - 1000: not in graph
pub fn get_follow_distance(txn: &Transaction, ndb: &Ndb, pubkey: &[u8; 32]) -> u32 {
    unsafe {
        bindings::ndb_socialgraph_get_follow_distance(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            pubkey.as_ptr(),
        )
    }
}

/// Check if one user follows another
pub fn is_following(txn: &Transaction, ndb: &Ndb, follower: &[u8; 32], followed: &[u8; 32]) -> bool {
    unsafe {
        bindings::ndb_socialgraph_is_following(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            follower.as_ptr(),
            followed.as_ptr(),
        ) != 0
    }
}

/// Get list of users followed by a user
///
/// Returns Vec of 32-byte pubkeys. May be truncated if user follows more than `max_out`.
pub fn get_followed(
    txn: &Transaction,
    ndb: &Ndb,
    pubkey: &[u8; 32],
    max_out: usize,
) -> Vec<[u8; 32]> {
    let mut buf = vec![0u8; max_out * 32];
    let count = unsafe {
        bindings::ndb_socialgraph_get_followed(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            pubkey.as_ptr(),
            buf.as_mut_ptr(),
            max_out as i32,
        )
    };

    let mut result = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[i * 32..(i + 1) * 32]);
        result.push(pk);
    }
    result
}

/// Get list of followers of a user
///
/// Returns Vec of 32-byte pubkeys. May be truncated if user has more than `max_out` followers.
pub fn get_followers(
    txn: &Transaction,
    ndb: &Ndb,
    pubkey: &[u8; 32],
    max_out: usize,
) -> Vec<[u8; 32]> {
    let mut buf = vec![0u8; max_out * 32];
    let count = unsafe {
        bindings::ndb_socialgraph_get_followers(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            pubkey.as_ptr(),
            buf.as_mut_ptr(),
            max_out as i32,
        )
    };

    let mut result = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[i * 32..(i + 1) * 32]);
        result.push(pk);
    }
    result
}

/// Get follower count for a user
pub fn follower_count(txn: &Transaction, ndb: &Ndb, pubkey: &[u8; 32]) -> usize {
    unsafe {
        bindings::ndb_socialgraph_follower_count(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            pubkey.as_ptr(),
        ) as usize
    }
}

/// Get followed count for a user (how many users they follow)
pub fn followed_count(txn: &Transaction, ndb: &Ndb, pubkey: &[u8; 32]) -> usize {
    unsafe {
        bindings::ndb_socialgraph_followed_count(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            pubkey.as_ptr(),
        ) as usize
    }
}

/// Set the root user for follow distance calculations
///
/// Recalculates all distances from the new root if changed.
/// This is async - queued to writer thread.
pub fn set_root(ndb: &Ndb, pubkey: &[u8; 32]) {
    unsafe {
        bindings::ndb_socialgraph_set_root(ndb.as_ptr(), pubkey.as_ptr());
    }
}

/// Check if one user mutes another
pub fn is_muting(txn: &Transaction, ndb: &Ndb, muter: &[u8; 32], muted: &[u8; 32]) -> bool {
    unsafe {
        bindings::ndb_socialgraph_is_muting(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            muter.as_ptr(),
            muted.as_ptr(),
        ) != 0
    }
}

/// Get list of users muted by a user
///
/// Returns Vec of 32-byte pubkeys. May be truncated if user mutes more than `max_out`.
pub fn get_muted(
    txn: &Transaction,
    ndb: &Ndb,
    pubkey: &[u8; 32],
    max_out: usize,
) -> Vec<[u8; 32]> {
    let mut buf = vec![0u8; max_out * 32];
    let count = unsafe {
        bindings::ndb_socialgraph_get_muted(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            pubkey.as_ptr(),
            buf.as_mut_ptr(),
            max_out as i32,
        )
    };

    let mut result = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[i * 32..(i + 1) * 32]);
        result.push(pk);
    }
    result
}

/// Get list of users who mute this user
///
/// Returns Vec of 32-byte pubkeys. May be truncated if more than `max_out` users mute this user.
pub fn get_muters(
    txn: &Transaction,
    ndb: &Ndb,
    pubkey: &[u8; 32],
    max_out: usize,
) -> Vec<[u8; 32]> {
    let mut buf = vec![0u8; max_out * 32];
    let count = unsafe {
        bindings::ndb_socialgraph_get_muters(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            pubkey.as_ptr(),
            buf.as_mut_ptr(),
            max_out as i32,
        )
    };

    let mut result = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[i * 32..(i + 1) * 32]);
        result.push(pk);
    }
    result
}

/// Get muter count for a user (how many users mute this user)
pub fn muter_count(txn: &Transaction, ndb: &Ndb, pubkey: &[u8; 32]) -> usize {
    unsafe {
        bindings::ndb_socialgraph_muter_count(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            pubkey.as_ptr(),
        ) as usize
    }
}

/// Check if a UID exists for a pubkey (has user been seen before)
pub fn uid_exists(txn: &Transaction, ndb: &Ndb, pubkey: &[u8; 32]) -> bool {
    unsafe {
        bindings::ndb_uid_exists(
            txn.as_mut_ptr(),
            ndb.as_ptr(),
            pubkey.as_ptr(),
        ) != 0
    }
}
