# Threading

- [Rust Book - Fearless Concurrency](https://doc.rust-lang.org/stable/book/ch16-00-concurrency.html)

Exucute parts of a program independently.

```rs
use std::thread;

fn main() {
    // Thread work definition
    let thread_fn = || {
        for i in 1..500 {
            println!("{i}");
        }
    };

    // Spawn detached thread 1
    let handle: JoinHandle<()> = thread::spawn(thread_fn);

    // Spawn detached thread 2
    let handle2: JoinHandle<()> = thread::spawn(thread_fn);

    // Check if threads are finished
    let handle_ready: bool = handle.is_finished();
    let handle2_ready: bool = handle2.is_finished();

    // Join handle 1
    handle.join().unwrap();

    // Join handle 2
    handle2.join().unwrap();
}
```

[is_finished](https://doc.rust-lang.org/stable/std/thread/struct.JoinHandle.html#method.is_finished)

Check if the thread has finished running

```rs
let ready: bool = handle.is_finished();
```
