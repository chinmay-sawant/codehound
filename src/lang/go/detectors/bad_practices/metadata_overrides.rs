pub const fn fix_for(id: u32) -> Option<&'static str> {
    match id {
        1 => Some("handle the error or explicitly ignore it with a comment"),
        2 => Some("wrap the error with operation-specific context"),
        3 => Some("return the error up the call stack instead of panicking"),
        4 => Some("log or otherwise surface the recovered panic before continuing"),
        5 => Some("check and handle the error returned by Close()"),
        6 => Some("call Add before starting the goroutine"),
        7 => Some("pass a pointer to the mutex or embed it in a pointer receiver"),
        8 => Some("avoid copying mutexes; lock and unlock the original pointer"),
        9 => Some("add a default branch, context cancellation, or timeout case"),
        10 => Some("reuse a time.Timer or time.Ticker outside the loop"),
        11 => Some("move cleanup after the loop or use an explicit closure"),
        12 => Some("add coordination between senders and receivers or move to taint-aware channel ownership analysis"),
        13 => Some("accept a context parameter and propagate it through calls"),
        14 => Some("thread cancellation through ctx.Done() or a done channel before spawning long-lived goroutines"),
        15 => Some("move recursive initialization outside the sync.Once.Do closure"),
        _ => None,
    }
}
