use async_std::task;
use async_std::sync::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

type NestedHashMap<K1, K2, V> = Arc<Mutex<HashMap<K1, HashMap<K2, V>>>>;

async fn insert_value<K1, K2, V>(
    map: NestedHashMap<K1, K2, V>,
    outer_key: K1,
    inner_key: K2,
    value: V,
) where
    K1: Eq + std::hash::Hash + Clone + 'static + Send,
    K2: Eq + std::hash::Hash + Clone + 'static + Send,
    V: Clone + 'static + Send,
{
    let mut map = map.lock().await;
    let inner_map = map.entry(outer_key.clone()).or_insert_with(HashMap::new);
    inner_map.insert(inner_key, value);
}

async fn get_value<K1, K2, V>(
    map: NestedHashMap<K1, K2, V>,
    outer_key: K1,
    inner_key: K2,
) -> Option<V>
where
    K1: Eq + std::hash::Hash + Clone + 'static + Send,
    K2: Eq + std::hash::Hash + Clone + 'static + Send,
    V: Clone + 'static + Send,
{
    let map = map.lock().await;
    map.get(&outer_key).and_then(|inner_map| inner_map.get(&inner_key)).cloned()
}

fn main() {
    task::block_on(async {
        let map: NestedHashMap<String, String, i32> = Arc::new(Mutex::new(HashMap::new()));
        let map_clone1 = Arc::clone(&map);
        let map_clone2 = Arc::clone(&map);

        let task1 = task::spawn(async move {
            insert_value(map_clone1.clone(), "outer1".to_string(), "inner1".to_string(), 10).await;
            insert_value(map_clone1, "outer1".to_string(), "inner2".to_string(), 20).await;
        });

        let task2 = task::spawn(async move {
            insert_value(map_clone2, "outer2".to_string(), "inner3".to_string(), 30).await;
        });

        task1.await;
        task2.await;

        if let Some(value) = get_value(Arc::clone(&map), "outer1".to_string(), "inner2".to_string()).await {
            println!("outer1:inner2: {}", value);
        } else {
            println!("Value not found");
        }

        if let Some(value) = get_value(Arc::clone(&map), "outer2".to_string(), "inner3".to_string()).await {
            println!("outer2:inner3: {}", value);
        } else {
            println!("Value not found");
        }
    });
}
