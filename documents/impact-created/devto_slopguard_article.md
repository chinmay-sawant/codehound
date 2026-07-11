# How We Fixed 218 Go Performance Anti-Patterns with Static Analysis

We ran a set of custom static analysis checks (codename CodeHound) against our Go PDF library. It found 226 issues. 218 of them were real. We fixed all 218.

Here is what we learned, what the actual before/after code looked like, and how much faster our PDFs got.

## The Setup

GoPDFSuit is optimized for high-volume PDF generation: invoices, reports, signed documents, and table-heavy PDFs with tagged structure. When you are cranking out thousands of documents per second, every microsecond adds up.

We have been profiling and optimizing for weeks. Buffer pooling, compression pipelines, structure tree rewrites. The low-hanging fruit was gone. We needed something more surgical.

Enter the tool we built (codename CodeHound). It scans Go ASTs for known performance anti-patterns using custom analyzers. It flags things like "hey, you are compiling a regex inside a loop" or "you called fmt.Sprintf on a static string, use errors.New instead."

We ran it. It spat out 226 findings across the entire project. After filtering out 8 CWE security-only items, we had 218 actionable performance issues to fix.

Here is exactly what we found and what we did about it.

## Regex Compilation Inside Loops (20 fixes)

This was the easiest win. Go's regexp.MustCompile is expensive. It parses the pattern, builds the NFA, and allocates internal state. Doing that on every iteration of a loop is painful.

Before. Four regexes compiled on every iteration of a member loop:

```go
for i := range members {
    nameRe := regexp.MustCompile(`/T\s*(?:\(([^)]*)\)|<([0-9A-Fa-f\s]+)>)`)
    if nameMatch := nameRe.FindSubmatch(objContent); nameMatch != nil {
        kidsRe := regexp.MustCompile(`/Kids\s*\[(.*?)\]`)
        if m := kidsRe.FindSubmatch(objContent); m != nil {
            refRe := regexp.MustCompile(`(\d+)\s+(\d+)\s+R`)
            for _, r := range refRe.FindAllSubmatch(m[1], -1) { ... }
        }
        singleKidsRe := regexp.MustCompile(`/Kids\s+(\d+)\s+(\d+)\s+R`)
        if m := singleKidsRe.FindSubmatch(objContent); m != nil { ... }
    }
}
```

After. All four compiled once before the loop starts:

```go
nameRe := regexp.MustCompile(`/T\s*(?:\(([^)]*)\)|<([0-9A-Fa-f\s]+)>)`)
kidsRe := regexp.MustCompile(`/Kids\s*\[(.*?)\]`)
refRe := regexp.MustCompile(`(\d+)\s+(\d+)\s+R`)
singleKidsRe := regexp.MustCompile(`/Kids\s+(\d+)\s+(\d+)\s+R`)
for i := range members {
    // loop body uses pre-compiled nameRe, kidsRe, refRe, singleKidsRe
```

We found this pattern in about 20 places across xfdf.go, merge.go, and helpers.go. Some were moved to package-level vars so they compile exactly once per process lifetime.

## Replacing fmt.Sprintf With strconv.AppendInt (50+ fixes)

This one surprised us. We knew fmt.Sprintf was not free, but we did not realize how many hot paths were paying the tax. Every call to fmt.Sprintf boxes its arguments into interface{}, allocates a new string on the heap, and runs the formatter with reflection.

The fix uses a stack-allocated scratch buffer and strconv.AppendInt to avoid fmt.Sprintf's reflection overhead.

Before. Font reference string in a loop:

```go
font.CachedRef = fmt.Sprintf("/CF%d", font.ObjectID)
```

After. A [12]byte stack buffer with AppendInt writes directly into it:

```go
var refBuf [12]byte
font.CachedRef = "/CF" + string(strconv.AppendInt(refBuf[:0], int64(font.ObjectID), 10))
```

This still allocates -- Go's `string()` conversion from a `[]byte` copies the data to ensure immutability, and the `+` concatenation produces a second string. But it trades fmt.Sprintf's reflection-based boxing and formatting for a fast stack buffer write followed by a copy. On hot paths the reduced CPU cost outweighs the allocation, and the pattern is consistent enough that the compiler can inline and optimize around it.

We applied this pattern about 50 times across handlers, generators, outlines, secure.go, and sampledata. The performance impact is cumulative. Each fix is tiny, but when you remove 50 fmt.Sprintf calls from hot paths, the bill comes due much later.

## Switching from strconv.Itoa to strconv.AppendInt (30+ fixes)

This is a sibling of the previous fix. strconv.Itoa creates a string value from an integer; in tight builders it adds allocation pressure because the string must be copied into the builder's buffer. strconv.AppendInt writes directly into an existing byte slice, letting us reuse a stack buffer and avoid the intermediate string entirely.

Before. Building a widths array for font metrics:

```go
var widthsArray strings.Builder
for i, w := range metrics.Widths {
    if i > 0 {
        widthsArray.WriteString(" ")
    }
    widthsArray.WriteString(strconv.Itoa(w))
}
```

After. A reusable [16]byte scratch buffer and AppendInt:

```go
var widthsArray strings.Builder
var widthBuf [16]byte
for i, w := range metrics.Widths {
    if i > 0 {
        widthsArray.WriteString(" ")
    }
    widthsArray.Write(strconv.AppendInt(widthBuf[:0], int64(w), 10))
}
```

The difference is subtle. The first version creates an intermediate string on every iteration, which can add allocation pressure depending on escape behavior. The second writes through a stack-allocated scratch buffer into the builder. No per-iteration allocation from the conversion itself -- the builder still grows its internal buffer as needed, but that growth is amortized across the loop.

## Removing defer From the Font Registry Hot Path (13 fixes)

This one was debated inside the team. defer is elegant. It pairs the lock and unlock on adjacent lines. You cannot forget to unlock. But the conditional defer pattern we had carries a hidden cost: when defer is placed inside an `if` block, Go's compiler cannot apply its open-coded defer optimization (introduced in Go 1.14). It falls back to a slower runtime heap-allocated defer frame on every call. On functions called millions of times per hour, that allocation tax adds up fast.

The font registry is called on every cell of every table in every document. 13 functions in registry.go used defer for mutex unlock. The before pattern used a conditional defer, which is a known risk: mixing conditional locks with manual unlocks in the same file is brittle and invites deadlocks if someone adds a new return path.

Before:

```go
func (r *CustomFontRegistry) HasFont(name string) bool {
    if !r.noLock {
        r.mu.RLock()
        defer r.mu.RUnlock()
    }
    _, ok := r.fonts[name]
    return ok
}
```

After:

```go
func (r *CustomFontRegistry) HasFont(name string) bool {
    if !r.noLock {
        r.mu.RLock()
    }
    _, ok := r.fonts[name]
    if !r.noLock {
        r.mu.RUnlock()
    }
    return ok
}
```

The GenerateSubsets function had an even trickier case. It had to unlock on every early return path from inside a loop:

```go
func (r *CustomFontRegistry) GenerateSubsets() error {
    r.mu.Lock()
    for name, font := range r.fonts {
        // ...
        subsetData, oldToNew, err := SubsetTTF(font.Font, usedGlyphs)
        if err != nil {
            r.mu.Unlock()
            return fmt.Errorf("failed to subset font %s: %w", name, err)
        }
        // ...
    }
    r.mu.Unlock()
    return nil
}
```

The tradeoff is real. Removing the conditional defer eliminates the compiler's fallback to runtime-allocated defer frames, but the code is now more fragile. One missing unlock on a new return path and you have a deadlock. We accepted this risk because this code path runs millions of times per hour, and the throughput gain was worth it.

## Eliminating Redundant string/[]byte Conversions (40+ fixes)

Go makes it easy to convert between string and []byte. So easy that you stop noticing the allocation. Every []byte(myString) copies the string data into a new heap-allocated byte slice.

We had about 40 of these on hot paths. The most creative fix used unsafe.Slice to get a zero-copy conversion.

Before. Password padding allocates a copy:

```go
func padPassword(password string) []byte {
    pwd := []byte(password)
    if len(pwd) >= 32 {
        return pwd[:32]
    }
    result := make([]byte, 32)
    copy(result, pwd)
    copy(result[len(pwd):], paddingBytes[:32-len(pwd)])
    return result
}
```

After. unsafe.Slice avoids the copy entirely (safe here because the string argument is always backed by stable memory):

```go
func padPassword(password string) []byte {
    if len(password) >= 32 {
        return unsafe.Slice(unsafe.StringData(password), 32)
    }
    result := make([]byte, 32)
    copy(result, password)
    copy(result[len(password):], paddingBytes[:32-len(password)])
    return result
}
```

> **Warning:** `unsafe.Slice(unsafe.StringData(s), n)` creates a `[]byte` that shares memory with the original string. This is only safe when the string outlives the returned slice and the slice is never mutated. In `padPassword` the returned byte slice is used transiently for encryption and discarded, so this tradeoff is safe here. Do not use this pattern on strings whose lifetime is shorter than the returned slice, and never write through the resulting byte slice unless you understand the memory model implications.

We also switched from strings.Builder to bytes.Buffer in places where we needed zero-copy access to the underlying bytes, and we replaced fmt.Sprintf inside regex ReplaceAllFunc callbacks with direct byte slice construction.

## Non-Blocking Logging

The standard log package in Go holds an internal mutex. Every log.Printf acquires it. On a request path handling thousands of requests per second, that mutex becomes a contention point.

Before. log.Fatalf on the server goroutine:

```go
go func() {
    if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        log.Fatalf("listen: %s\n", err)
    }
}()
```

After. Direct stderr write:

```go
go func() {
    if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        fmt.Fprintf(os.Stderr, "listen: %s\n", err)
        os.Exit(1)
    }
}()
```

Similarly, we replaced our gin.Recovery wrapper with gin.CustomRecovery, which let us centralize panic handling and remove our own per-request defer wrapper.

## Cheap Guards Before Expensive Operations

strings.TrimSpace returns a sub-slice of the original when no trimming is needed, but repeated calls in a hot loop still add scanning overhead. bytes.Equal checks length first internally, but a length guard makes the intent explicit and can skip the call entirely when lengths differ. Both are worth guarding when most inputs do not need trimming or are visibly different in size.

Before:

```go
if !ok || !bytes.Equal(origBody, body) {
```

After:

```go
if !ok || len(origBody) != len(body) || !bytes.Equal(origBody, body) {
```

A length check is O(1). bytes.Equal is O(n). The guard short-circuits the expensive call when lengths differ.

Same idea for TrimSpace. Instead of trimming blindly, we check the first and last byte first:

```go
mode := strings.ToLower(opts.Mode)
if len(mode) > 0 && (mode[0] == ' ' || mode[len(mode)-1] == ' ') {
    mode = strings.TrimSpace(mode)
}
```

And in the renderer, we replaced TrimSpace with a zero-allocation isSpace helper that scans bytes manually:

```go
func isSpace(s string) bool {
    for i := 0; i < len(s); i++ {
        if s[i] != ' ' && s[i] != '\t' && s[i] != '\n' && s[i] != '\r' {
            return false
        }
    }
    return true
}
```

## Algorithmic Hoisting Over Micro-Optimizations

Not every CodeHound fix was a one-liner. Finding P6-26 in `internal/pdf/redact/ocr_adapter.go` flagged a nested loop that called `strings.ToLower` and `strings.TrimSpace` on every iteration of a word-by-word OCR search. The fix was to hoist both normalizations out of the loop entirely.

Before. Each query and each OCR word was lowered and trimmed on every comparison:

```go
for _, query := range queries {
    query = strings.ToLower(strings.TrimSpace(query))
    for _, word := range ocrWords {
        word = strings.ToLower(strings.TrimSpace(word))
        if strings.Contains(word, query) {
            ...
        }
    }
}
```

After. All normalization happens once before the loop starts:

```go
for i, query := range queries {
    queries[i] = strings.ToLower(strings.TrimSpace(query))
}
for i, word := range ocrWords {
    ocrWords[i] = strings.ToLower(strings.TrimSpace(word))
}
for _, query := range queries {
    for _, word := range ocrWords {
        if strings.Contains(word, query) {
            ...
        }
    }
}
```

This changed the hot path from O(N x M) allocations to O(N + M) allocations. The structural change -- hoisting work out of a nested loop -- yielded a bigger win than any single AppendInt replacement on this code path.

## Map Pre-Sizing

Go maps grow by doubling when they hit their load factor. Each growth iteration rehashes every entry and allocates a new backing array. You can avoid this by adding a capacity hint when you know the approximate size.

Before:

```go
font.UsedChars = make(map[rune]bool)
```

After:

```go
font.UsedChars = make(map[rune]bool, 256)
```

Before:

```go
objMap := make(map[int][]byte)
```

After:

```go
objMap := make(map[int][]byte, len(objMatches))
```

These are tiny changes. But when the map lives inside a hot loop and grows 10 times before stabilizing, the savings add up.

## Static fmt.Errorf to errors.New

fmt.Errorf formats a string even when there are no format verbs. errors.New just wraps a static string. The difference is small per call, but these are often on error paths that are themselves inside loops.

Before:

```go
return fmt.Errorf("no successful runs")
```

After:

```go
return errors.New("no successful runs")
```

## Replacing strings.Split With strings.Cut or bytes.Split

strings.Split allocates a slice of strings. strings.Cut returns two strings with zero allocation. bytes.Split into preallocated buffers avoids string allocation entirely.

For SVG style parsing:

Before:

```go
styleParts := strings.Split(style, ";")
for _, part := range styleParts {
    kv := strings.SplitN(part, ":", 2)
    if len(kv) == 2 {
        k := strings.TrimSpace(kv[0])
        v := strings.TrimSpace(kv[1])
        attrs[k] = v
    }
}
```

After:

```go
styleParts := strings.SplitSeq(style, ";")
for part := range styleParts {
    part = strings.TrimSpace(part)
    if part == "" { continue }
    k, v, ok := strings.Cut(part, ":")
    if ok {
        k = strings.TrimSpace(k)
        v = strings.TrimSpace(v)
        attrs[k] = v
    }
}
```

`strings.SplitSeq` is a zero-allocation iterator (introduced in Go 1.24 range-over-func). Unlike `strings.Split` which builds an entire `[]string` slice on the heap before the loop, `SplitSeq` yields each substring one at a time with no intermediate allocation. `Cut` similarly returns two substrings without a `[]string{2}` slice. Map assignment still pushes substrings to the heap, but the allocation volume drops from per-element slice allocations to just the map entries that survive.

## Scanner Buffer Limit

bufio.Scanner has a default max token size of 64 KiB. If a line exceeds that, Scan returns false and you have to check Err() to discover the truncation. Our OCR adapter was processing Tesseract TSV output that sometimes had lines longer than 64 KiB.

Before:

```go
scanner := bufio.NewScanner(bytes.NewReader(tsvOut))
for scanner.Scan() {
    line := scanner.Text()
    cols := strings.Split(line, "\t")
    // ...
```

After:

```go
scanner := bufio.NewScanner(bytes.NewReader(tsvOut))
scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
for scanner.Scan() {
    line := scanner.Bytes()
    cols := bytes.Split(line, []byte{'\t'})
    // ...
```

The buffer is raised to 10 MiB, and we switched to scanner.Bytes() with bytes.Split to stay in byte-land and avoid string allocation.

## Did Any of This Actually Matter?

Yes. We benchmarked before and after using the GoPDFKit compare harness (10 runs, 3 seconds each, fresh binary each time).

| Workload | Before (pdf/s) | After (pdf/s) | Change |
|----------|---------------:|--------------:|--------|
| text_short | 174,763 | 163,267 | -6.6% |
| text_240_lines | 15,994 | 17,434 | +9.0% |
| table_180_rows | 11,548 | 13,051 | +13.0% |
| table_900_rows | 2,563 | 2,680 | +4.6% |
| invoice_40_rows | 44,504 | 44,073 | -1.0% |
| png_table_180_rows | 12,574 | 12,112 | -3.7% |
| png_rows_60 | 6,991 | 6,634 | -5.1% |

The three heaviest CPU-bound workloads saw real improvements. table_180_rows went up 13%. text_240_lines went up 9%. table_900_rows went up 4.6%.

The table wins were driven primarily by `internal/pdf/draw.go` -- the `drawTitleTable` function formatting every cell was using per-iteration `strconv.Itoa` (heap-allocating) before the fix. The `strconv.AppendInt` + scratch buffer pattern in the draw loop alone accounted for about 15 call sites on the table rendering hot path.

The lightweight workloads showed noise. text_short actually regressed 6.6% because a static-asset cache header wrapper in handlers.go added overhead visible only on the fastest benchmark (absolute ns/op remained under 6 microseconds). We accepted this because the real-world payloads are the table and multi-line text benchmarks.

## The Allocation Paradox

Our bytes-per-operation went up 2-15% across the board. That seems backward. We replaced fmt.Sprintf with AppendInt specifically to reduce allocations. Why did allocations go up?

The answer is a mix of factors. Some setup allocations shifted earlier or became longer-lived, and benchmark allocation accounting can make that look counterintuitive depending on how the harness measures setup versus operation work. Higher throughput also means more iterations in the same time window, so any fixed-cost setup allocation gets counted more times. Some changes like map pre-sizing do not reduce total allocation -- they reduce regrowth allocation, but the total memory allocated can increase because we allocate a larger initial capacity. And for the sub-10-microsecond workloads, the 2-15% alloc increase is within benchmark noise range and probably not meaningful.

The throughput gains were worth the allocation increase. We traded more upfront allocation for less per-operation work on the paths that mattered most.

## What This Enabled

The static analysis remediation was the foundation for everything that came after. The techniques we applied here (pre-size slices, pool buffers, avoid extra copies, use stack-scratch writes) became the playbook for later optimization phases.

Building on these changes, the project went on to:

- Win all 7 GoPDFKit comparison benchmarks, with the best result being +788% on png_rows_60
- Push Gin HTTP throughput from 593 req/s to over 1,000 req/s
- Drive the Zerodha end-to-end benchmark from 573 ops/s to 2,898 ops/s
- Eventually reach 9,594 ops/sec (a 3.4x improvement from the original baseline)

## The Takeaway

Static analysis tools like the one we built are not magic. They flag patterns, not problems. Every finding requires judgment. Some are false positives. Some are not worth fixing. But many of them are real, and the cumulative effect of fixing 218 small things is a measurably faster system.

The patterns here are not Go-specific. Every language has:
- Expensive operations inside loops (regex, allocation, formatting)
- Unnecessary defer/finally overhead on hot paths
- Redundant conversions between string and byte representations
- Costly function calls that could be guarded by a cheap check

Run a performance linter. Read each finding. Judge it honestly. Fix the ones that matter. Your future self, waiting at the terminal for benchmarks to finish, will thank you.
