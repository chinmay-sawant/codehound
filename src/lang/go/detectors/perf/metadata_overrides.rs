/// Default severity for Go performance rules.
///
/// PERF rules are medium severity by default: they do not block compilation or
/// deployment, they signal a likely hot-path improvement. Individual rule ids
/// can override this in [`fix_for`] / [`severity_for`] pairs.
pub const fn severity_for(_id: u32) -> crate::rules::Severity {
    crate::rules::Severity::Medium
}

pub const fn fix_for(id: u32) -> Option<&'static str> {
    match id {
        // PERF-1: Regex compile reuse
        1 => Some("Compile the regular expression once at package scope and reuse the compiled pattern."),
        // PERF-2: String builder reuse
        2 => Some("Hoist a strings.Builder (or preallocated bytes.Buffer) outside the loop and reuse it via Reset."),
        // PERF-3: Slice reuse in loop
        3 => Some("Hoist the slice out of the loop and reuse it via [:0] or a preallocated make with capacity."),
        // PERF-4: Map reuse in loop
        4 => Some("Move the make call out of the loop and reuse the map via clear() or by passing it in."),
        // PERF-5: Marshal reuse in loop
        5 => Some("Marshal or unmarshal once outside the loop, or stream with a reused encoder/decoder."),
        // PERF-6: fmt buffer reuse
        6 => Some("Use a bytes.Buffer, strings.Builder, or pool of buffers to avoid repeated fmt allocations."),
        // PERF-7: Defer in loop
        7 => Some("Replace the defer with explicit close calls inside the loop or move the work into a helper function."),
        // PERF-8: time.Parse in loop
        8 => Some("Hoist time.Parse out of the loop or cache parsed time values keyed by layout."),
        // PERF-9: url.Parse in loop
        9 => Some("Parse each URL once outside the loop and store the *url.URL value."),
        // PERF-10: Template compile reuse
        10 => Some("Compile templates at process start with template.Must and reuse the parsed template."),
        // PERF-11: HTTP client reuse
        11 => Some("Reuse a single http.Client (and Transport) declared at package scope."),
        // PERF-12: SQL prepare reuse
        12 => Some("Prepare the statement once at startup and reuse it, or use a connection-pooled helper."),
        // PERF-13: time.Timer reuse
        13 => Some("Use a reusable *time.Timer with Stop+Reset, or a single time.Ticker, instead of time.After."),
        // PERF-14: Glob/ReadDir in loop
        14 => Some("Hoist filepath.Glob / os.ReadDir out of the loop and cache the directory listing."),
        // PERF-15: String concat optimization
        15 => Some("Use a strings.Builder or strconv.Append* to avoid repeated allocations."),
        // PERF-16: bytes.Buffer reuse
        16 => Some("Reuse a single bytes.Buffer by calling Reset at the start of each iteration."),
        // PERF-17: String builder in loop
        17 => Some("Hoist a strings.Builder outside the loop or use strings.Join to avoid repeated concatenation."),
        // PERF-18: Unnecessary slice copy
        18 => Some("Pass a reslice of the original slice instead of copying when the callee does not mutate."),
        // PERF-19: Range value copy
        19 => Some("Range by index (&slice[i]) or pointer to avoid copying each struct value."),
        // PERF-20: Reflection in hot path
        20 => Some("Cache reflect.Type / reflect.Value at startup, or use code generation to avoid hot-path reflection."),
        // PERF-21: Stream request body
        21 => Some("Stream the request body via json.NewDecoder or io.Copy instead of fully buffering with io.ReadAll."),
        // PERF-22: File read in handler
        22 => Some("Load the file once at startup, or stream it, instead of reading on the request path."),
        // PERF-23: Buffer pool for reader
        23 => Some("Use a sync.Pool of *bytes.Reader or reuse a buffer across requests."),
        // PERF-24: Hasher reuse
        24 => Some("Hoist the hasher out of the loop and call h.Reset() each iteration instead of allocating a new hasher."),
        // PERF-25: Key pair generation reuse
        25 => Some("Generate the key pair once at startup and reuse the private key across requests."),
        // PERF-26: base64 encoder reuse
        26 => Some("Hoist base64.NewEncoder/Decoder outside the loop, or reuse a single encoder with a pooled bytes.Buffer."),
        // PERF-27: sync.Pool for buffer
        27 => Some("Wrap the buffer in sync.Pool and call Get/Put around the hot section."),
        // PERF-28: Mutex in struct
        28 => Some("Embed the mutex in a long-lived struct (package or request-scoped pool) instead of a per-request literal."),
        // PERF-29: Unbounded goroutines
        29 => Some("Bound goroutines with a worker pool, semaphore channel, or errgroup with SetLimit."),
        // PERF-30: context.Background in goroutine
        30 => Some("Propagate c.Request.Context() or the caller's context to the goroutine instead of context.Background()."),
        // PERF-31: Defer cleanup in loop
        31 => Some("Move the cleanup into a helper function that returns a Close() method called from a single defer outside the loop."),
        // PERF-32: Unsafe conversion
        32 => Some("Use unsafe conversions only in measured hot paths, or hoist the conversion outside the loop with a pooled buffer."),
        // PERF-33: Full slice scan
        33 => Some("Use an indexed scan with an explicit break when you only need the first match, or stream the slice."),
        // PERF-34: Map-to-slice preallocation
        34 => Some("Preallocate the destination slice with make([]T, 0, len(m)) before the range loop."),
        // PERF-35: Interface boxing
        35 => Some("Cast non-string args to a concrete type or use strconv/strings builders to avoid interface boxing."),
        // PERF-36: Loop variable capture
        36 => Some("Copy the loop variable into a per-iteration local (v := v) before launching the goroutine."),
        // PERF-37: Zero-alloc append
        37 => Some("Replace the var declaration with make([]T, 0, hint) to give the runtime a growth target."),
        // PERF-38: Unbuffered channel
        38 => Some("Use make(chan T, N) with a buffer sized to expected concurrency."),
        // PERF-39: Busy-loop select
        39 => Some("Use a time.Sleep backoff or remove the default branch to avoid busy-looping."),
        // PERF-40: time.Now in hot path
        40 => Some("Hoist time.Now() outside the function, or cache the value in a struct field, when measuring a single event."),
        // PERF-41: Structured logging
        41 => Some("Route logs through a structured logger (slog/zap/zerolog) and gate debug levels with build tags."),
        // PERF-42: errors.New vs fmt.Errorf
        42 => Some("Use errors.New or a sentinel error when the message has no format verbs."),
        // PERF-43: recover in handler
        43 => Some("Move recover() to a middleware boundary instead of a per-request defer."),
        // PERF-44: Repeated type assertion
        44 => Some("Bind the asserted value to a local once (v, ok := x.(T)) and reuse the binding."),
        // PERF-45: Slice preallocation
        45 => Some("Preallocate with make([]T, 0, hint) before the loop so append does not reallocate."),
        // PERF-46: strings.TrimSpace
        46 => Some("Use strings.TrimFunc with an explicit predicate, or check s == strings.TrimSpace(s) before allocating."),
        // PERF-47: strings.Split allocation
        47 => Some("Use strings.SplitSeq or a manual index loop over strings.IndexByte to avoid the []string allocation."),
        // PERF-48: Early string comparison
        48 => Some("Add an early length-mismatch or prefix check before the comparison."),
        // PERF-49: copy pre-size buffer
        49 => Some("Validate the payload length and size the destination buffer to the exact count before copy()."),
        // PERF-50: Regex in loop
        50 => Some("Compile the regex once with regexp.MustCompile and call re.MatchString in the loop."),
        // PERF-51: Unsafe string conversion
        51 => Some("Replace the unsafe conversion with strconv.Quote/Unquote or a measured []byte(s) outside the loop."),
        // PERF-52: runtime.GC call
        52 => Some("Remove runtime.GC; the runtime already manages collection, and manual calls slow the allocator."),
        // PERF-53: math/rand locality
        53 => Some("Use a per-goroutine rand.NewSource(rand.New(rand.NewSource(time.Now().UnixNano()))) or math/rand/v2."),
        // PERF-54: Global strings.Builder
        54 => Some("Hoist a *strings.Builder at package scope and call b.Reset() before each reuse."),
        // PERF-55: bufio.Scanner buffer
        55 => Some("Call scanner.Buffer(make([]byte, initial), max) before Scan to size the token buffer."),
        // PERF-56: Batched JSON response
        56 => Some("Collect the response items into a slice and call c.JSON once, or stream with c.Stream."),
        // PERF-57: Heavy parsing in middleware
        57 => Some("Move heavy parsing (io.ReadAll/json.Unmarshal) out of middleware into the handler, or cache the result."),
        // PERF-58: Missing body close
        58 => Some("Add defer c.Request.Body.Close() after every access, or drain with io.Copy(io.Discard, body)."),
        // PERF-59: Repeated binding
        59 => Some("Bind once into a pre-validated struct or share a custom binding.Validator across handlers."),
        // PERF-60: render reuse
        60 => Some("Reuse a single render.JSON / render.HTML instance created at startup, or use c.Render / c.HTML."),
        // PERF-61: Cache-Control headers
        61 => Some("Add explicit Cache-Control / ETag headers via c.Header() before serving static content."),
        // PERF-62: Path param middleware
        62 => Some("Parse path parameters once at registration time, not in middleware on every request."),
        // PERF-63: Validator cache
        63 => Some("Cache binding.Validator.Engine() in a package-level variable and reuse it across requests."),
        // PERF-64: c.Copy for goroutine
        64 => Some("Call c.Copy() before launching the goroutine so the context survives the request lifetime."),
        // PERF-65: Bind in middleware
        65 => Some("Move c.ShouldBindJSON out of shared middleware into the leaf handler that owns the payload."),
        // PERF-66: Middleware flattening
        66 => Some("Flatten the middleware chain or merge small middlewares into a single function."),
        // PERF-67: Missing gin.Recovery
        67 => Some("Add gin.Recovery() (or gin.RecoveryWithWriter) to gin.New() to avoid panics taking down the process."),
        // PERF-68: gin.Logger in production
        68 => Some("Replace gin.Logger() with gin.LoggerWithConfig(gin.LoggerConfig{Output: io.Discard, ...}) in production."),
        // PERF-69: c.Writer.Flush
        69 => Some("Call c.Writer.Flush() (or c.Writer.Flush()) after c.Writer.Write to flush the response in chunks."),
        // PERF-70: Goroutine lifecycle
        70 => Some("Tie the goroutine to a sync.WaitGroup, a done channel, or c.Request.Context() so it cannot outlive the request."),
        // PERF-71: GORM N+1 — Preload
        71 => Some("Use db.Preload(\"Orders\") (or db.Joins) before the iteration, or batch the query with WHERE user_id IN (?)."),
        // PERF-72: Unnecessary transaction
        72 => Some("Drop the transaction wrapper when the work is a single read or single statement."),
        // PERF-73: GORM Preload relation
        73 => Some("Call db.Preload(\"Relation\") on the parent query so GORM hydrates the relation in one round trip."),
        // PERF-74: GORM SELECT projection
        74 => Some("Add .Select(\"id, name, email\") to project only the columns the handler actually returns."),
        // PERF-75: GORM session reuse
        75 => Some("Hoist the gorm.Session config to a package-level var and reuse it via db.WithContext(...)."),
        // PERF-76: GORM batch insert
        76 => Some("Use db.CreateInBatches(rows, 100) (or insertBuilder) instead of calling db.Create per row."),
        // PERF-77: GORM partial update
        77 => Some("Use db.Update(\"field\", value) or db.Updates(map[string]any{...}) when only a subset of fields changes."),
        // PERF-78: Missing index
        78 => Some("Add the corresponding index in the migration file (or use FORCE INDEX in the query) to back the WHERE/ORDER BY clause."),
        // PERF-79: DB pool config
        79 => Some("Call db.SetMaxOpenConns / SetMaxIdleConns / SetConnMaxLifetime once at startup."),
        // PERF-80: GORM unbounded Pluck
        80 => Some("Add .Limit(N) (or chunk via FindInBatches) to bound the slice Pluck returns."),
        // PERF-81: Large IN clause
        81 => Some("Chunk the slice into groups of 100–500 and run multiple db.Select queries."),
        // PERF-82: sqlx row scan
        82 => Some("Use rows.StructScan with a small destination struct, or use sqlx.Select to scan into a preallocated slice."),
        // PERF-83: Map scan destination
        83 => Some("Pre-declare a map[string]any with the expected columns, or use rows.Scan with explicit destinations."),
        // PERF-84: Transaction for single op
        84 => Some("Drop the transaction wrapper for single-statement work, or batch the work inside a shorter transaction."),
        // PERF-85: sqlx named query reuse
        85 => Some("Pre-build the named query once and reuse it inside the loop (sqlx.NamedExec with a cached statement)."),
        // PERF-86: Echo stream/encoder pool
        86 => Some("Batch responses with c.Stream, or reuse a json.Encoder with a sync.Pool to avoid reallocation."),
        // PERF-87: Echo validation skip
        87 => Some("Skip full validation in trusted paths, or share a custom echo.Binder across handlers."),
        // PERF-88: Echo static headers
        88 => Some("Add Cache-Control / ETag headers to e.Static or the static middleware."),
        // PERF-89: Middleware heavy init
        89 => Some("Move heavy parsing (make / json.Unmarshal) out of middleware or wrap the middleware behind sync.Once."),
        // PERF-90: Echo context payload
        90 => Some("Use c.Set with small scalar values (user_id, request_id, trace_id) and propagate context instead of large payloads."),
        // PERF-91: Fiber buffer pooling
        91 => Some("Use fasthttp's bytebufferpool or c.Request.BodyStream() to avoid per-request allocations."),
        // PERF-92: Fiber goroutine ctx
        92 => Some("Copy needed fields out of c before launching the goroutine, or use c.UserContext() to scope the lifetime."),
        // PERF-93: Fiber JSON encoder pool
        93 => Some("Reuse a json.Encoder via sync.Pool, or stream responses with c.SendStream."),
        // PERF-94: Fiber body copy
        94 => Some("Use c.Body() / c.RequestBodyStream() as a []byte and avoid io.ReadAll on fasthttp streams."),
        // PERF-95: Fiber middleware grouping
        95 => Some("Consolidate overlapping middlewares or attach them once at the app level instead of nested groups."),
        // PERF-96: gRPC message allocation
        96 => Some("Allocate the message once outside the loop and call msg.Reset() between stream.RecvMsg calls."),
        // PERF-97: proto.Marshal buffer reuse
        97 => Some("Reuse a MarshalOptions or a pooled bytes.Buffer across iterations to avoid per-call allocation."),
        // PERF-98: go-redis pipeline
        98 => Some("Wrap the redis calls in rdb.Pipeline().Exec(ctx) or rdb.Pipelined(ctx, ...) to batch the round trips."),
        // PERF-99: Prometheus high-cardinality
        99 => Some("Replace high-cardinality labels (user_id, uuid, path) with low-cardinality aggregates (status, method, route)."),
        // PERF-100: Cobra flag registration
        100 => Some("Move heavy RunE work into a function and reuse flag registration via a pre-built flag.FlagSet."),
        // PERF-102: Multiple WriteHeader
        102 => Some("WriteHeader can only be called once per response; set the status via WriteHeader(status) before the first Write."),
        // PERF-106: sync.Map write-heavy + cache bounding
        106 => Some("Replace sync.Map with a plain map guarded by a sync.Mutex when the workload is write-heavy; sync.Map's read/dirty dual-map structure only pays off for read-heavy, key-stable workloads. If used as a cache, add eviction bounds: entry cap, byte cap, or TTL to prevent unbounded growth under concurrent load."),
        // PERF-108: sort.Search in loop
        108 => Some("Hoist sort.Search out of the loop; if the search space changes per iteration, cache the index instead."),
        // PERF-110: sync.Pool pointer type
        110 => Some("Return a pointer type from sync.Pool's New function (e.g. *Foo) so Put does not box the value back into the pool."),
        // PERF-114: for-range copy → copy()
        114 => Some("Replace the manual for-range copy with the copy() builtin; copy() uses memmove and handles memory overlap."),
        // PERF-119: Consecutive append merge
        119 => Some("Merge the consecutive append calls into a single variadic append, e.g. s = append(s, a, b, c)."),
        // PERF-121: Direct type conversion
        121 => Some("Use a direct type conversion (T(x)) when the source and target structs have identical field types."),
        // PERF-125: Nil guard on append
        125 => Some("Drop the `if s != nil` guard; append handles a nil slice by allocating a new backing array."),
        // PERF-128: 3+ consecutive append merge
        128 => Some("Merge the 3+ consecutive append calls into a single variadic append; each separate call can grow the backing array independently."),
        // PERF-129: Range index vs value
        129 => Some("Use `for i := range xs` to skip copying the value when the loop body only needs the index."),
        // PERF-130: Inline func wrapper
        130 => Some("Inline the call: drop the `func() { ... }()` wrapper when the body is a single call expression."),
        // PERF-131: Atomic vs mutex
        131 => Some("Replace the mutex with sync/atomic for simple counter-style mutations; atomics compile to a single instruction."),
        // PERF-132: Request context in goroutine
        132 => Some("Pass the request context into the goroutine: go func() { db.QueryContext(ctx, ...) }() so the request lifetime cancels the work."),
        // PERF-133: sort.Slice in loop
        133 => Some("Hoist sort.Slice out of the loop, or use sort.Sort with a sort.Interface type that doesn't allocate a closure per call."),
        // PERF-135: gob.NewEncoder reuse
        135 => Some("Hoist gob.NewEncoder/Decoder to a single instance created at startup; the constructor does reflection that should not run per loop iteration."),
        // PERF-137: runtime.Caller in hot path
        137 => Some("Avoid runtime.Caller on the hot path; pass a stack index as a constant or use a faster source-location API."),
        // PERF-140: debug.SetGCPercent
        140 => Some("Remove the debug.SetGCPercent(-1) call (it disables the GC assist entirely) or set it above 50 unless GOMEMLIMIT is also configured."),
        // PERF-141: r.URL.Query() cache
        141 => Some("Cache r.URL.Query() in a local variable at the top of the handler; subsequent calls re-parse the query string."),
        // PERF-145: r.WithContext reuse
        145 => Some("Hoist the request context to a long-lived middleware boundary; r.WithContext allocates a new *http.Request per call."),
        // PERF-149: Connection deadline
        149 => Some("Set a deadline before conn.Read / conn.Write with conn.SetReadDeadline / SetWriteDeadline to avoid hanging the request."),
        // PERF-156: Rune range vs byte range
        156 => Some("Use `for i := range s` to skip UTF-8 decoding; the rune binding is only useful when the value is read."),
        // PERF-158: slices.Sort vs sort.Slice
        158 => Some("Use slices.Sort for []int / []string / []float64; sort.Slice allocates a closure per call and reflects on the comparator."),
        // PERF-161: rows.Err after Next
        161 => Some("Call rows.Err() after the rows.Next() loop to distinguish 'no more rows' from a real error."),
        // PERF-163: QueryRow for single row
        163 => Some("Use db.QueryRow for single-row queries; it handles rows.Close() for you."),
        // PERF-165: sql.Scanner on custom type
        165 => Some("Implement sql.Scanner on the custom type so rows.Scan can decode directly without manual extraction."),
        // PERF-166: sql.Null types
        166 => Some("Use sql.NullString / sql.NullInt64 in the scan target; the database/sql package exposes typed null wrappers."),
        // PERF-168: Pointer to channel
        168 => Some("Send a pointer to the struct over the channel: ch <- &Large{...} to avoid copying every field."),
        // PERF-170: sync.Once in hot path
        170 => Some("Hoist sync.Once out of hot paths; use a sync/atomic.Bool or a plain package-level var for cheap one-time init."),
        // PERF-171: Channel as mutex
        171 => Some("Use a sync.Mutex for acquire/release; channels used as mutexes add an extra scheduling hop and a heap-allocated channel struct."),
        // PERF-176: io.CopyBuffer
        176 => Some("Use io.CopyBuffer with a pooled *[]byte; io.Copy allocates a 32 KiB buffer per call."),
        // PERF-177: os.ReadDir vs ioutil.ReadDir
        177 => Some("Call os.ReadDir(name) to get []os.DirEntry; switch to os.ReadDir for new code."),
        // PERF-181: json.Decoder UseNumber
        181 => Some("Call decoder.UseNumber() before Decode when the target struct has int/int64 fields, to avoid silent float64 precision loss for big numbers."),
        // PERF-182: bufio.Writer buffer size
        182 => Some("Pass an explicit buffer size to bufio.NewWriter(w, size) when the downstream Write calls are larger than the default 4 KiB buffer."),
        // PERF-192: Map preallocation
        192 => Some("Pass the expected size: make(map[K]V, len(src)) before the population loop to avoid map growth."),
        // PERF-195: log.Fatal in goroutine
        195 => Some("Return the error from the goroutine instead of calling log.Fatal; the caller decides whether to terminate the process."),
        // PERF-204: GORM Updates with Select
        204 => Some("Add a .Select(\"col1\", \"col2\") call before db.Updates(map) so GORM only writes the columns you intend."),
        // PERF-209: Cobra PersistentPreRunE → sync.Once
        209 => Some("Move shared initialization out of PersistentPreRunE into a sync.Once in the parent command, or into a setup function called once at startup."),
        // PERF-211: GORM Not/NotIn → positive list
        211 => Some("Replace db.Not() / NOT IN with an explicit positive list (WHERE id IN (?)) so the query planner can use the index."),
        // PERF-213: Cache bounding/eviction
        213 => Some("Add an eviction boundary to the cache: limit entries (max N), limit retained bytes (max M), or add TTL-based expiry so the cache cannot grow unbounded under load."),
        // PERF-214: Cache key volatility
        214 => Some("Remove volatile fields (pointer addresses, request IDs, coordinates) from the cache key. Key only on fields that are stable across repeated identical calls."),
        // PERF-215: Buffer pre-sizing
        215 => Some("Pre-size the bytes.Buffer or strings.Builder by calling Grow(expectedSize) when the final content size is known or can be estimated from input parameters."),
        // PERF-216: Arena/slab allocation
        216 => Some("Replace individual per-element heap allocations in the hot path with a slab or arena allocator that pre-allocates contiguous blocks for the struct type."),
        // PERF-217: Static computation caching
        217 => Some("Cache the deterministic computation result in a package-level variable computed at init(); the output never changes per request."),
        // PERF-218: Per-CPU pool sharding
        218 => Some("Replace the single contended sync.Pool with per-CPU shards (e.g., a [runtime.NumCPU()]sync.Pool array) to reduce lock contention under high concurrency."),
        // PERF-219: Oversized pool discard
        219 => Some("Guard the Put call: if cap(obj) > maxSize { return } to discard oversized buffers instead of returning them to the pool."),
        // PERF-220: Double-scan merge
        220 => Some("Merge the consecutive loops over the same data into a single pass that does all required work, eliminating the redundant iteration overhead."),
        // PERF-221: map[int] → []T
        221 => Some("Replace map[int]T with []T when the integer keys are dense and sequential (e.g. indices, counters). Use make([]T, maxKey+1) and direct index access."),
        // PERF-222: Generics in hot path
        222 => Some("Replace the generic function on the measured hot path with a concrete type or use code generation. Shape-based dispatch prevents inlining and adds call overhead."),
        // PERF-223: Pool backing array retention
        223 => Some("Retain backing array capacity on pool return: use obj.Reset() (obj.Slice = obj.Slice[:0]) instead of obj.Slice = nil so the backing array is reused on next acquire."),
        // PERF-224: Iterative tree walk
        224 => Some("Replace the recursive tree walk with an iterative loop over the existing flat pre-ordered representation of the same data."),
        // PERF-225: Redundant large slice clone
        225 => Some("Keep a single owned buffer: clone once, or mutate in place when the source is exclusive. Avoid chaining slices.Clone / append([]T(nil), …) on the same data."),
        // PERF-226: Post-producer re-copy
        226 => Some("Return or use the producer buffer directly after Bytes()/Close(). Only copy when the source must go back to a pool, and copy before Put — not after an exclusive local."),
        // PERF-227: Compress writer pool
        227 => Some("Pool flate/zlib/gzip writers and call Reset(dst) on each use instead of NewWriter on every encode."),
        // PERF-228: Tiny parallel fan-out
        228 => Some("For worksets of 1–2 items, run the work serially instead of errgroup/WaitGroup/go fan-out; spawn cost usually dominates."),
        // PERF-229: Intermediate string → append
        229 => Some("Write numbers/text into the destination with strconv.AppendInt / AppendUint / AppendFloat (or Builder) instead of Itoa/Sprintf then append([]byte(s))."),
        // PERF-230: Loop-invariant pure call
        230 => Some("Hoist the pure call before the loop or cache its result when arguments do not change across iterations."),
        // PERF-231: PEM/key parse on hot path
        231 => Some("Parse PEM/keys once at process start (package var or sync.Once) and reuse *rsa.PrivateKey / certificates on the hot path."),
        // PERF-232: Unbounded parallel fan-out
        232 => Some("Cap fan-out with errgroup.SetLimit or a semaphore before spawning per-item work."),
        // PERF-233: Slow compress level on hot path
        233 => Some("Use flate/zlib BestSpeed (or level 1) for hot stream compression when size budgets allow. Reserve Default/BestCompression for cold or archival paths."),
        // PERF-234: Bulk buffer without workload sizing
        234 => Some("Grow bulk buffers from a workload estimate (payload length, item count), not a large fixed default or bare pool Reset."),
        // PERF-236: Full buffer clone on signing path
        236 => Some("Keep an owned writable buffer with reserved holes, or mutate in place, instead of bytes.Clone of the entire document on the signing path."),
        _ => None,
    }
}
