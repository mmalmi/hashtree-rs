//! Extensive tests for HashTree - unified merkle tree operations
//!
//! Tests matching and exceeding hashtree-ts test coverage

use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use hashtree::{
    DirEntry, HashTree, HashTreeConfig, HashTreeError, Link, MemoryStore, Store, to_hex,
};

fn make_tree() -> (Arc<MemoryStore>, HashTree<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let tree = HashTree::new(HashTreeConfig::new(store.clone()));
    (store, tree)
}

fn make_tree_with_chunk_size(chunk_size: usize) -> (Arc<MemoryStore>, HashTree<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let tree = HashTree::new(HashTreeConfig::new(store.clone()).with_chunk_size(chunk_size));
    (store, tree)
}

// ============ CREATE TESTS ============

mod create {
    use super::*;

    #[tokio::test]
    async fn test_store_small_file_as_single_blob() {
        let (_store, tree) = make_tree();

        let data = b"hello world";
        let result = tree.put_file(data).await.unwrap();

        assert_eq!(result.size, 11);
        assert_eq!(result.hash.len(), 32);

        let retrieved = tree.read_file(&result.hash).await.unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_chunk_large_files() {
        let (_, tree) = make_tree_with_chunk_size(10);
        let data = b"this is a longer message that will be chunked";

        let result = tree.put_file(data).await.unwrap();
        assert_eq!(result.size, data.len() as u64);

        let retrieved = tree.read_file(&result.hash).await.unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_create_empty_directory() {
        let (_store, tree) = make_tree();

        let hash = tree.put_directory(vec![], None).await.unwrap();

        let entries = tree.list_directory(&hash).await.unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[tokio::test]
    async fn test_create_directory_with_entries() {
        let (_store, tree) = make_tree();

        let file1 = tree.put_file(b"content1").await.unwrap();
        let file2 = tree.put_file(b"content2").await.unwrap();

        let dir_hash = tree
            .put_directory(
                vec![
                    DirEntry::new("a.txt", file1.hash).with_size(8),
                    DirEntry::new("b.txt", file2.hash).with_size(8),
                ],
                None,
            )
            .await
            .unwrap();

        let entries = tree.list_directory(&dir_hash).await.unwrap();
        assert_eq!(entries.len(), 2);

        let mut names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["a.txt", "b.txt"]);
    }

    #[tokio::test]
    async fn test_directory_entries_sorted() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_blob(b"data").await.unwrap();

        let dir_hash = tree
            .put_directory(
                vec![
                    DirEntry::new("zebra", file_hash),
                    DirEntry::new("apple", file_hash),
                    DirEntry::new("mango", file_hash),
                ],
                None,
            )
            .await
            .unwrap();

        let node = tree.get_tree_node(&dir_hash).await.unwrap().unwrap();
        let names: Vec<_> = node.links.iter().filter_map(|l| l.name.clone()).collect();
        // Should be sorted alphabetically
        assert_eq!(names, vec!["apple", "mango", "zebra"]);
    }

    #[tokio::test]
    async fn test_put_tree_node_with_metadata() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_blob(b"data").await.unwrap();

        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), serde_json::json!(2));
        metadata.insert("author".to_string(), serde_json::json!("test"));

        let node_hash = tree
            .put_tree_node(
                vec![Link::new(file_hash).with_name("file.txt").with_size(4)],
                Some(metadata),
            )
            .await
            .unwrap();

        let node = tree.get_tree_node(&node_hash).await.unwrap().unwrap();
        assert!(node.metadata.is_some());
        let m = node.metadata.unwrap();
        assert_eq!(m.get("version"), Some(&serde_json::json!(2)));
        assert_eq!(m.get("author"), Some(&serde_json::json!("test")));
    }

    #[tokio::test]
    async fn test_file_deduplication() {
        let (store, tree) = make_tree_with_chunk_size(100);

        let repeated_chunk = vec![42u8; 100];
        let data: Vec<u8> = repeated_chunk.iter().cycle().take(500).cloned().collect();

        let result = tree.put_file(&data).await.unwrap();
        assert_eq!(result.size, 500);

        // Store should have fewer items due to deduplication
        // (1 unique chunk + tree nodes)
        let store_size = store.size();
        assert!(store_size < 5, "Expected deduplication, got {} items", store_size);

        // Verify can still read back
        let retrieved = tree.read_file(&result.hash).await.unwrap().unwrap();
        assert_eq!(retrieved.len(), 500);
    }

    #[tokio::test]
    async fn test_nested_directory_structure() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_blob(b"deep content").await.unwrap();

        let deep_dir = tree
            .put_directory(vec![DirEntry::new("file.txt", file_hash).with_size(12)], None)
            .await
            .unwrap();

        let mid_dir = tree
            .put_directory(vec![DirEntry::new("deep", deep_dir)], None)
            .await
            .unwrap();

        let root_dir = tree
            .put_directory(vec![DirEntry::new("mid", mid_dir)], None)
            .await
            .unwrap();

        // Verify structure
        let resolved = tree.resolve_path(&root_dir, "mid/deep/file.txt").await.unwrap();
        assert_eq!(resolved, Some(file_hash));
    }
}

// ============ READ TESTS ============

mod read {
    use super::*;

    #[tokio::test]
    async fn test_read_file() {
        let (_store, tree) = make_tree();

        let data = b"test content";
        let result = tree.put_file(data).await.unwrap();

        let read_data = tree.read_file(&result.hash).await.unwrap();
        assert_eq!(read_data, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_read_missing_file() {
        let (_store, tree) = make_tree();

        let missing_hash = [0u8; 32];
        let result = tree.read_file(&missing_hash).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_directory() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_file(b"data").await.unwrap();
        let dir_hash = tree
            .put_directory(vec![DirEntry::new("file.txt", file_hash.hash).with_size(4)], None)
            .await
            .unwrap();

        let entries = tree.list_directory(&dir_hash).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "file.txt");
    }

    #[tokio::test]
    async fn test_resolve_path() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_file(b"nested").await.unwrap();
        let sub_dir_hash = tree
            .put_directory(vec![DirEntry::new("file.txt", file_hash.hash).with_size(6)], None)
            .await
            .unwrap();
        let root_hash = tree
            .put_directory(vec![DirEntry::new("subdir", sub_dir_hash).with_size(6)], None)
            .await
            .unwrap();

        let resolved = tree.resolve_path(&root_hash, "subdir/file.txt").await.unwrap();
        assert!(resolved.is_some());
        assert_eq!(to_hex(&resolved.unwrap()), to_hex(&file_hash.hash));
    }

    #[tokio::test]
    async fn test_resolve_path_missing() {
        let (_store, tree) = make_tree();

        let dir_hash = tree.put_directory(vec![], None).await.unwrap();

        let resolved = tree.resolve_path(&dir_hash, "nonexistent/path").await.unwrap();
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn test_check_if_hash_is_directory() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_file(b"data").await.unwrap();
        let dir_hash = tree.put_directory(vec![], None).await.unwrap();

        assert!(!tree.is_directory(&file_hash.hash).await.unwrap());
        assert!(tree.is_directory(&dir_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_is_tree() {
        let (_store, tree) = make_tree();

        let blob_hash = tree.put_blob(b"raw data").await.unwrap();
        let dir_hash = tree.put_directory(vec![], None).await.unwrap();

        assert!(!tree.is_tree(&blob_hash).await.unwrap());
        assert!(tree.is_tree(&dir_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_size_blob() {
        let (_store, tree) = make_tree();

        let data = b"test data for size";
        let hash = tree.put_blob(data).await.unwrap();

        let size = tree.get_size(&hash).await.unwrap();
        assert_eq!(size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_get_size_chunked_file() {
        let (_store, tree) = make_tree_with_chunk_size(100);

        let data = vec![0u8; 500];
        let result = tree.put_file(&data).await.unwrap();

        let size = tree.get_size(&result.hash).await.unwrap();
        assert_eq!(size, 500);
    }

    #[tokio::test]
    async fn test_read_file_chunks() {
        let (_store, tree) = make_tree_with_chunk_size(10);

        let data = b"hello world!!!";
        let result = tree.put_file(data).await.unwrap();

        let chunks = tree.read_file_chunks(&result.hash).await.unwrap();
        assert!(chunks.len() > 1); // Should be multiple chunks

        // Reconstruct
        let combined: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(combined, data.to_vec());
    }

    #[tokio::test]
    async fn test_walk() {
        let (_store, tree) = make_tree();

        let f1 = tree.put_blob(b"1").await.unwrap();
        let f2 = tree.put_blob(b"23").await.unwrap();

        let sub_dir = tree
            .put_directory(vec![DirEntry::new("nested.txt", f2).with_size(2)], None)
            .await
            .unwrap();

        let root_dir = tree
            .put_directory(
                vec![
                    DirEntry::new("root.txt", f1).with_size(1),
                    DirEntry::new("sub", sub_dir),
                ],
                None,
            )
            .await
            .unwrap();

        let entries = tree.walk(&root_dir, "").await.unwrap();
        let paths: Vec<_> = entries.iter().map(|e| e.path.as_str()).collect();

        assert!(paths.contains(&""));
        assert!(paths.contains(&"root.txt"));
        assert!(paths.contains(&"sub"));
        assert!(paths.contains(&"sub/nested.txt"));
    }

    #[tokio::test]
    async fn test_get_tree_node() {
        let (_store, tree) = make_tree();

        let blob_hash = tree.put_blob(b"data").await.unwrap();
        let dir_hash = tree
            .put_directory(vec![DirEntry::new("file.txt", blob_hash)], None)
            .await
            .unwrap();

        // Blob should return None
        let blob_node = tree.get_tree_node(&blob_hash).await.unwrap();
        assert!(blob_node.is_none());

        // Directory should return TreeNode
        let dir_node = tree.get_tree_node(&dir_hash).await.unwrap();
        assert!(dir_node.is_some());
        assert_eq!(dir_node.unwrap().links.len(), 1);
    }
}

// ============ STREAMING TESTS ============

mod streaming {
    use super::*;

    #[tokio::test]
    async fn test_read_file_stream_small() {
        let (_store, tree) = make_tree();

        let data = b"small data";
        let result = tree.put_file(data).await.unwrap();

        let mut stream = tree.read_file_stream(result.hash);
        let mut collected = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            collected.extend(chunk_result.unwrap());
        }

        assert_eq!(collected, data.to_vec());
    }

    #[tokio::test]
    async fn test_read_file_stream_chunked() {
        let (_store, tree) = make_tree_with_chunk_size(5);

        let data = b"hello world!";
        let result = tree.put_file(data).await.unwrap();

        let mut stream = tree.read_file_stream(result.hash);
        let mut chunks = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            chunks.push(chunk_result.unwrap());
        }

        assert!(chunks.len() > 1);

        let combined: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(combined, data.to_vec());
    }

    #[tokio::test]
    async fn test_read_file_stream_missing() {
        let (_store, tree) = make_tree();

        let missing_hash = [0u8; 32];
        let mut stream = tree.read_file_stream(missing_hash);

        let result = stream.next().await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_read_file_stream_large() {
        let (_store, tree) = make_tree_with_chunk_size(100);

        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let result = tree.put_file(&data).await.unwrap();

        let mut stream = tree.read_file_stream(result.hash);
        let mut total_size = 0;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.unwrap();
            total_size += chunk.len();
        }

        assert_eq!(total_size, 1000);
    }

    #[tokio::test]
    async fn test_walk_stream() {
        let (_store, tree) = make_tree();

        let f1 = tree.put_blob(b"1").await.unwrap();
        let f2 = tree.put_blob(b"23").await.unwrap();

        let sub_dir = tree
            .put_directory(vec![DirEntry::new("nested.txt", f2).with_size(2)], None)
            .await
            .unwrap();

        let root_dir = tree
            .put_directory(
                vec![
                    DirEntry::new("root.txt", f1).with_size(1),
                    DirEntry::new("sub", sub_dir),
                ],
                None,
            )
            .await
            .unwrap();

        let mut stream = tree.walk_stream(root_dir, "".to_string());
        let mut paths = Vec::new();

        while let Some(entry_result) = stream.next().await {
            let entry = entry_result.unwrap();
            paths.push(entry.path);
        }

        assert!(paths.contains(&"".to_string()));
        assert!(paths.contains(&"root.txt".to_string()));
        assert!(paths.contains(&"sub".to_string()));
        assert!(paths.contains(&"sub/nested.txt".to_string()));
    }

    #[tokio::test]
    async fn test_walk_stream_single_file() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_blob(b"content").await.unwrap();

        let mut stream = tree.walk_stream(file_hash, "file.txt".to_string());
        let mut entries = Vec::new();

        while let Some(entry_result) = stream.next().await {
            entries.push(entry_result.unwrap());
        }

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "file.txt");
        assert!(!entries[0].is_tree);
        assert_eq!(entries[0].size, Some(7));
    }
}

// ============ EDIT TESTS ============

mod edit {
    use super::*;

    #[tokio::test]
    async fn test_add_entry_to_directory() {
        let (_store, tree) = make_tree();

        let root_hash = tree.put_directory(vec![], None).await.unwrap();
        let file = tree.put_file(b"hello").await.unwrap();

        let new_root = tree
            .set_entry(&root_hash, &[], "test.txt", file.hash, file.size)
            .await
            .unwrap();

        let entries = tree.list_directory(&new_root).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "test.txt");
    }

    #[tokio::test]
    async fn test_update_existing_entry() {
        let (_store, tree) = make_tree();

        let file1 = tree.put_file(b"v1").await.unwrap();
        let root_hash = tree
            .put_directory(vec![DirEntry::new("file.txt", file1.hash).with_size(2)], None)
            .await
            .unwrap();

        let file2 = tree.put_file(b"v2 updated").await.unwrap();
        let new_root = tree
            .set_entry(&root_hash, &[], "file.txt", file2.hash, file2.size)
            .await
            .unwrap();

        let entries = tree.list_directory(&new_root).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(to_hex(&entries[0].hash), to_hex(&file2.hash));
    }

    #[tokio::test]
    async fn test_remove_entry() {
        let (_store, tree) = make_tree();

        let file1 = tree.put_file(b"a").await.unwrap();
        let file2 = tree.put_file(b"b").await.unwrap();
        let root_hash = tree
            .put_directory(
                vec![
                    DirEntry::new("a.txt", file1.hash).with_size(1),
                    DirEntry::new("b.txt", file2.hash).with_size(1),
                ],
                None,
            )
            .await
            .unwrap();

        let new_root = tree.remove_entry(&root_hash, &[], "a.txt").await.unwrap();

        let entries = tree.list_directory(&new_root).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "b.txt");
    }

    #[tokio::test]
    async fn test_rename_entry() {
        let (_store, tree) = make_tree();

        let file = tree.put_file(b"content").await.unwrap();
        let root_hash = tree
            .put_directory(vec![DirEntry::new("old.txt", file.hash).with_size(7)], None)
            .await
            .unwrap();

        let new_root = tree
            .rename_entry(&root_hash, &[], "old.txt", "new.txt")
            .await
            .unwrap();

        let entries = tree.list_directory(&new_root).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "new.txt");
        assert_eq!(to_hex(&entries[0].hash), to_hex(&file.hash));
    }

    #[tokio::test]
    async fn test_rename_same_name_no_change() {
        let (_store, tree) = make_tree();

        let file = tree.put_file(b"content").await.unwrap();
        let root_hash = tree
            .put_directory(vec![DirEntry::new("file.txt", file.hash)], None)
            .await
            .unwrap();

        let new_root = tree
            .rename_entry(&root_hash, &[], "file.txt", "file.txt")
            .await
            .unwrap();

        assert_eq!(to_hex(&new_root), to_hex(&root_hash));
    }

    #[tokio::test]
    async fn test_move_entry_between_directories() {
        let (_store, tree) = make_tree();

        let file = tree.put_file(b"content").await.unwrap();
        let dir1_hash = tree
            .put_directory(vec![DirEntry::new("file.txt", file.hash).with_size(7)], None)
            .await
            .unwrap();
        let dir2_hash = tree.put_directory(vec![], None).await.unwrap();
        let root_hash = tree
            .put_directory(
                vec![
                    DirEntry::new("dir1", dir1_hash).with_size(7),
                    DirEntry::new("dir2", dir2_hash).with_size(0),
                ],
                None,
            )
            .await
            .unwrap();

        let new_root = tree
            .move_entry(&root_hash, &["dir1"], "file.txt", &["dir2"])
            .await
            .unwrap();

        let entries = tree.list_directory(&new_root).await.unwrap();
        assert_eq!(entries.len(), 2);

        let dir1_entries = tree
            .list_directory(&tree.resolve_path(&new_root, "dir1").await.unwrap().unwrap())
            .await
            .unwrap();
        assert_eq!(dir1_entries.len(), 0);

        let dir2_entries = tree
            .list_directory(&tree.resolve_path(&new_root, "dir2").await.unwrap().unwrap())
            .await
            .unwrap();
        assert_eq!(dir2_entries.len(), 1);
        assert_eq!(dir2_entries[0].name, "file.txt");
    }

    #[tokio::test]
    async fn test_nested_path_edits() {
        let (_store, tree) = make_tree();

        let c_hash = tree.put_directory(vec![], None).await.unwrap();
        let b_hash = tree
            .put_directory(vec![DirEntry::new("c", c_hash).with_size(0)], None)
            .await
            .unwrap();
        let a_hash = tree
            .put_directory(vec![DirEntry::new("b", b_hash).with_size(0)], None)
            .await
            .unwrap();
        let root_hash = tree
            .put_directory(vec![DirEntry::new("a", a_hash).with_size(0)], None)
            .await
            .unwrap();

        let file = tree.put_file(b"deep").await.unwrap();
        let new_root = tree
            .set_entry(&root_hash, &["a", "b", "c"], "file.txt", file.hash, file.size)
            .await
            .unwrap();

        // Verify nested file
        let entries = tree
            .list_directory(&tree.resolve_path(&new_root, "a/b/c").await.unwrap().unwrap())
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "file.txt");

        // Verify parent structure intact
        let a_entries = tree
            .list_directory(&tree.resolve_path(&new_root, "a").await.unwrap().unwrap())
            .await
            .unwrap();
        assert_eq!(a_entries.len(), 1);
        assert_eq!(a_entries[0].name, "b");
    }

    #[tokio::test]
    async fn test_set_entry_path_not_found() {
        let (_store, tree) = make_tree();

        let root_hash = tree.put_directory(vec![], None).await.unwrap();
        let file = tree.put_file(b"data").await.unwrap();

        let result = tree
            .set_entry(&root_hash, &["nonexistent"], "file.txt", file.hash, file.size)
            .await;

        assert!(matches!(result, Err(HashTreeError::PathNotFound(_))));
    }

    #[tokio::test]
    async fn test_rename_entry_not_found() {
        let (_store, tree) = make_tree();

        let root_hash = tree.put_directory(vec![], None).await.unwrap();

        let result = tree
            .rename_entry(&root_hash, &[], "nonexistent.txt", "new.txt")
            .await;

        assert!(matches!(result, Err(HashTreeError::EntryNotFound(_))));
    }

    #[tokio::test]
    async fn test_immutable_edit_operations() {
        let (_store, tree) = make_tree();

        let file = tree.put_file(b"original").await.unwrap();
        let original_root = tree
            .put_directory(vec![DirEntry::new("file.txt", file.hash).with_size(8)], None)
            .await
            .unwrap();

        let file2 = tree.put_file(b"modified").await.unwrap();
        let new_root = tree
            .set_entry(&original_root, &[], "file.txt", file2.hash, file2.size)
            .await
            .unwrap();

        // Original unchanged
        let original_entries = tree.list_directory(&original_root).await.unwrap();
        assert_eq!(to_hex(&original_entries[0].hash), to_hex(&file.hash));

        // New root has changes
        let new_entries = tree.list_directory(&new_root).await.unwrap();
        assert_eq!(to_hex(&new_entries[0].hash), to_hex(&file2.hash));
    }
}

// ============ VERIFY TESTS ============

mod verify {
    use super::*;
    use hashtree::hashtree_verify_tree;

    #[tokio::test]
    async fn test_verify_valid_tree() {
        let (store, tree) = make_tree_with_chunk_size(100);

        let data = vec![0u8; 350];
        let result = tree.put_file(&data).await.unwrap();

        let verify_result = hashtree_verify_tree(store, &result.hash).await.unwrap();
        assert!(verify_result.valid);
        assert!(verify_result.missing.is_empty());
    }

    #[tokio::test]
    async fn test_verify_missing_chunk() {
        let (store, tree) = make_tree_with_chunk_size(100);

        let data = vec![0u8; 350];
        let result = tree.put_file(&data).await.unwrap();

        // Delete one chunk
        let keys = store.keys();
        if let Some(chunk_to_delete) = keys.iter().find(|k| **k != result.hash) {
            store.delete(chunk_to_delete).await.unwrap();
        }

        let verify_result = hashtree_verify_tree(store, &result.hash).await.unwrap();
        assert!(!verify_result.valid);
        assert!(!verify_result.missing.is_empty());
    }
}

// ============ EDGE CASES ============

mod edge_cases {
    use super::*;

    #[tokio::test]
    async fn test_empty_file() {
        let (_store, tree) = make_tree();

        let result = tree.put_file(&[]).await.unwrap();
        assert_eq!(result.size, 0);

        let data = tree.read_file(&result.hash).await.unwrap().unwrap();
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn test_single_byte_file() {
        let (_store, tree) = make_tree();

        let result = tree.put_file(&[42]).await.unwrap();
        assert_eq!(result.size, 1);

        let data = tree.read_file(&result.hash).await.unwrap().unwrap();
        assert_eq!(data, vec![42]);
    }

    #[tokio::test]
    async fn test_exact_chunk_size() {
        let (_store, tree) = make_tree_with_chunk_size(100);

        let data = vec![0u8; 100];
        let result = tree.put_file(&data).await.unwrap();

        let read_data = tree.read_file(&result.hash).await.unwrap().unwrap();
        assert_eq!(read_data.len(), 100);
    }

    #[tokio::test]
    async fn test_chunk_size_plus_one() {
        let (_store, tree) = make_tree_with_chunk_size(100);

        let data = vec![0u8; 101];
        let result = tree.put_file(&data).await.unwrap();

        let read_data = tree.read_file(&result.hash).await.unwrap().unwrap();
        assert_eq!(read_data.len(), 101);
    }

    #[tokio::test]
    async fn test_binary_data() {
        let (_store, tree) = make_tree();

        let data: Vec<u8> = (0..=255).cycle().take(512).collect();
        let result = tree.put_file(&data).await.unwrap();

        let read_data = tree.read_file(&result.hash).await.unwrap().unwrap();
        assert_eq!(read_data, data);
    }

    #[tokio::test]
    async fn test_special_characters_in_names() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_blob(b"data").await.unwrap();

        let dir_hash = tree
            .put_directory(
                vec![
                    DirEntry::new("file with spaces.txt", file_hash),
                    DirEntry::new("file-with-dashes.txt", file_hash),
                    DirEntry::new("file_with_underscores.txt", file_hash),
                    DirEntry::new("file.multiple.dots.txt", file_hash),
                ],
                None,
            )
            .await
            .unwrap();

        let entries = tree.list_directory(&dir_hash).await.unwrap();
        assert_eq!(entries.len(), 4);
    }

    #[tokio::test]
    async fn test_unicode_names() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_blob(b"data").await.unwrap();

        let dir_hash = tree
            .put_directory(
                vec![
                    DirEntry::new("日本語.txt", file_hash),
                    DirEntry::new("émoji🎉.txt", file_hash),
                    DirEntry::new("中文文件.txt", file_hash),
                ],
                None,
            )
            .await
            .unwrap();

        let entries = tree.list_directory(&dir_hash).await.unwrap();
        assert_eq!(entries.len(), 3);

        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"日本語.txt"));
        assert!(names.contains(&"émoji🎉.txt"));
        assert!(names.contains(&"中文文件.txt"));
    }

    #[tokio::test]
    async fn test_deeply_nested_path() {
        let (_store, tree) = make_tree();

        // Create 10 levels deep
        let file_hash = tree.put_blob(b"deep content").await.unwrap();
        let mut current_hash = tree
            .put_directory(vec![DirEntry::new("file.txt", file_hash)], None)
            .await
            .unwrap();

        for i in (1..=10).rev() {
            current_hash = tree
                .put_directory(vec![DirEntry::new(format!("level{}", i), current_hash)], None)
                .await
                .unwrap();
        }

        let path = "level1/level2/level3/level4/level5/level6/level7/level8/level9/level10/file.txt";
        let resolved = tree.resolve_path(&current_hash, path).await.unwrap();
        assert_eq!(resolved, Some(file_hash));
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let (_store, tree) = make_tree();

        // Create multiple files concurrently
        let futures: Vec<_> = (0..10)
            .map(|i| {
                let t = &tree;
                async move {
                    let data = vec![i as u8; 100];
                    t.put_file(&data).await
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        for result in results {
            assert!(result.is_ok());
        }
    }
}

// ============ INTEROPERABILITY TESTS ============

mod interop {
    use super::*;

    #[tokio::test]
    async fn test_hash_consistency() {
        let (_store1, tree1) = make_tree();
        let (_store2, tree2) = make_tree();

        let data = b"test data for hash consistency";

        let result1 = tree1.put_file(data).await.unwrap();
        let result2 = tree2.put_file(data).await.unwrap();

        // Same data should produce same hash
        assert_eq!(to_hex(&result1.hash), to_hex(&result2.hash));
    }

    #[tokio::test]
    async fn test_directory_hash_consistency() {
        let (_store1, tree1) = make_tree();
        let (_store2, tree2) = make_tree();

        // Create same structure in both
        let file1_1 = tree1.put_file(b"content1").await.unwrap();
        let file1_2 = tree1.put_file(b"content2").await.unwrap();
        let dir1 = tree1
            .put_directory(
                vec![
                    DirEntry::new("a.txt", file1_1.hash).with_size(8),
                    DirEntry::new("b.txt", file1_2.hash).with_size(8),
                ],
                None,
            )
            .await
            .unwrap();

        let file2_1 = tree2.put_file(b"content1").await.unwrap();
        let file2_2 = tree2.put_file(b"content2").await.unwrap();
        let dir2 = tree2
            .put_directory(
                vec![
                    DirEntry::new("b.txt", file2_2.hash).with_size(8), // Different order
                    DirEntry::new("a.txt", file2_1.hash).with_size(8),
                ],
                None,
            )
            .await
            .unwrap();

        // Should produce same hash due to sorting
        assert_eq!(to_hex(&dir1), to_hex(&dir2));
    }
}
