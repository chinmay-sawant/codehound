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
        12 => Some(
            "add coordination between senders and receivers or move to taint-aware channel ownership analysis",
        ),
        13 => Some("accept a context parameter and propagate it through calls"),
        14 => Some(
            "thread cancellation through ctx.Done() or a done channel before spawning long-lived goroutines",
        ),
        15 => Some("move recursive initialization outside the sync.Once.Do closure"),
        72 => Some("return a nil interface instead of a typed nil pointer"),
        73 => Some("initialize the local map with make before indexing it"),
        79 => Some("release the locally owned context cancellation function on every path"),
        84 => Some("convert to floating point before dividing to calculate a percentage"),
        101 => Some("set the response status before writing the response body"),
        67 => Some("pass the errors.As target by address"),
        75 => Some("allocate the copy destination with a non-zero length before copying"),
        80 => Some("propagate a real caller context or use an explicit lifecycle context"),
        88 => Some(
            "initialize the channel with make or use it only in an intentional nil-channel select",
        ),
        98 => Some("close the opened file or explicitly transfer ownership to the caller"),
        99 => Some("lock the Cond locker before calling Wait"),
        109 => Some("abort or return immediately after writing the Gin error response"),
        116 => Some("choose either Echo response handling or raw error propagation, not both"),
        131 => Some("use Exec or ExecContext for DML that does not return rows"),
        145 => Some("release or close the acquired pgx pool connection on every path"),
        159 => Some("call flag.Parse before reading flag pointer values"),
        68 => {
            Some("return or assign the errors.Join result instead of discarding the combined error")
        }
        85 => Some("check the ok result from Context.Value before using the asserted value"),
        102 => {
            Some("write an HTTP error response or status before returning from the failure path")
        }
        136 => Some("run GORM AutoMigrate during startup or a dedicated migration command"),
        142 => Some("call Rebind on the sqlx.In query before executing it"),
        151 => Some("redact the environment value or log only whether the secret is configured"),
        162 => Some("avoid mutating package-level state from a parallel test"),
        164 => {
            Some("apply the functional option to the supplied instance instead of global defaults")
        }
        66 => Some("use errors.Is instead of comparing a wrapped sentinel with == or !="),
        86 => Some(
            "unlock the same mutex on every path, preferably with defer immediately after Lock",
        ),
        87 => Some("copy the protected state and release the read lock before blocking"),
        89 => Some("ensure one owner closes the channel at most once"),
        110 => Some("check the Gin bind error before using the request"),
        117 => Some("check or return the Echo bind error before continuing"),
        120 => Some("check or return the Fiber BodyParser error before continuing"),
        138 => Some("move external I/O out of the GORM hook and run it after commit"),
        141 => Some("add matching db tags or configure the sqlx mapper explicitly"),
        161 => {
            Some("use a local or container database target in tests instead of a production DSN")
        }
        163 => Some("skip golden-file update writes in short tests with testing.Short"),
        76 => Some("sort map-derived values before using them as ordered output"),
        81 => Some("capture time.Now once before comparing multiple deadlines"),
        90 => Some("add a cancellation, select, break, or return path to the receive loop"),
        91 => Some("use a signal-only channel or send meaningful data when the channel carries a value"),
        92 => Some("derive the errgroup from a context with errgroup.WithContext"),
        93 => Some("return the operation error from the errgroup closure"),
        94 => Some("protect shared map writes with synchronization or an ownership boundary"),
        96 => Some("check the rows error and close the rows value on every path"),
        97 => Some("flush the writer before reading from its underlying buffer"),
        100 => Some("bound goroutine fan-out with a worker pool, semaphore, or errgroup limit"),
        104 => Some("remove the duplicate ServeMux pattern or make the route patterns distinct"),
        105 => Some("set Secure and HttpOnly on sensitive cookies"),
        107 => Some("call the next handler or write an explicit terminal response"),
        122 => Some("call the next Chi middleware or write an explicit terminal response"),
        128 => Some("distinguish sql.ErrNoRows from other QueryRow.Scan failures"),
        132 => Some("check RowsAffected and handle an optimistic-lock conflict"),
        133 => Some("check the GORM chain Error before using the result"),
        134 => Some("handle gorm.ErrRecordNotFound separately from other query errors"),
        135 => Some("use a request-scoped GORM session instead of a mutable global chain"),
        140 => Some("check or return the sqlx retrieval error"),
        143 => Some("check or return the Redis command result error"),
        146 => Some("redact sensitive fields before logging"),
        147 => Some("use the structured logger consistently in service code"),
        149 => Some("include the error value as a structured logging attribute"),
        155 => Some("limit the request body before decoding JSON"),
        156 => Some("avoid omitempty for security-sensitive JSON fields or validate zero values explicitly"),
        _ => None,
    }
}
