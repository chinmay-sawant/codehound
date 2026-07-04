# P2 PERF Rules Extension — Executive Summary

**Date:** June 2026  
**Scope:** Extended PERF rules from 100 → 212 by adding 112 new performance anti-pattern rules sourced from verified Go references.

---

## Process

| Step | Action | Result |
|------|--------|--------|
| 1 | Launched 10 source agents | ~403 raw candidate rules gathered |
| 2 | Batch 1 dedup (staticcheck, gocritic, Uber/Google, runtime, net/http) | 56 verified unique rules |
| 3 | Batch 2 dedup (database/SQL, concurrency, stdlib, books, frameworks) | 63 verified unique rules |
| 4 | Cross-batch dedup validation | 7 cross-batch duplicates removed, 4 existing-rule duplicates removed |
| **Final** | Merged into `ruleset/golang/golang.json` | **112 new rules** (PERF-101 through PERF-212) |

## Verification

- Zero duplicate names with existing 100 PERF rules
- Zero duplicate names among the 112 new rules
- Sequential numbering: PERF-1 through PERF-212
- All validated against: staticcheck SA/S1xxx, gocritic, Uber/Google Go Style Guides, Go wiki Performance, Go wiki CommonMistakes, "100 Go Mistakes" (Harsanyi), "Efficient Go" (Plotka), "Concurrency in Go" (Cox-Buday), Go runtime source, Go release notes

---

## Source Breakdown

| Source | Rules Contributed |
|--------|:---:|
| staticcheck (SA/S1xxx checks) | ~25 |
| gocritic diagnostics | ~15 |
| Uber/Google Go Style Guides | ~18 |
| Go runtime (escape analysis, GC, scheduler) | ~12 |
| net/http, httptest, httputil | ~14 |
| database/sql, GORM, sqlx | ~16 |
| sync, channels, atomic, context | ~10 |
| encoding, io, os, crypto, sort | ~14 |
| Web frameworks (chi, mux, gRPC, OTel, zap, viper) | ~12 |
| 100 Go Mistakes, Efficient Go, Concurrency in Go | ~10 |
| **Total (after cross-source dedup)** | **112** |

---

## New Rules

| ID | Name |
|----|------|
| PERF-101 | HTTP Server Timeouts Not Configured |
| PERF-102 | HTTP Transport Not Shared Across Requests |
| PERF-103 | HTTP Response Body Not Closed |
| PERF-104 | WriteHeader Called Multiple Times In Handler |
| PERF-105 | runtime.SetFinalizer On Hot Path Object |
| PERF-106 | sync.Map Used For Write-Heavy Workload |
| PERF-107 | encoding/binary Write Or Read Inside Loop |
| PERF-108 | sort.Search Repeated In Loop |
| PERF-109 | Map Key Recomputed In Loop Without Caching |
| PERF-110 | sync.Pool Element Type Causes Allocation On Put |
| PERF-111 | Range Over String Produces Rune Allocation |
| PERF-112 | strings.ToLower Before Comparison Instead Of EqualFold |
| PERF-113 | Single-Case Select Statement Instead Of Channel Op |
| PERF-114 | Manual Loop Copy Instead Of copy() Builtin |
| PERF-115 | strings.Compare Used For Equality Check |
| PERF-116 | strings.Index Used For Contains Check |
| PERF-117 | bytes.Compare Used For Equality Check |
| PERF-118 | Unnecessary http.NewRequest For Simple Methods |
| PERF-119 | Multiple Separate Appends Instead Of Spread Concatenation |
| PERF-120 | time.Now().Sub Instead Of time.Since |
| PERF-121 | Struct Literal Instead Of Direct Type Conversion |
| PERF-122 | HasPrefix Followed By Slice Instead Of TrimPrefix |
| PERF-123 | Redundant make Argument With Zero Value |
| PERF-124 | strings.Replace With -1 Instead Of ReplaceAll |
| PERF-125 | Redundant nil Check Before append |
| PERF-126 | Redundant http.CanonicalHeaderKey Call |
| PERF-127 | Unnecessary fmt.Sprintf In Log Call |
| PERF-128 | Multiple Independent Appends Can Be Combined |
| PERF-129 | Range Loop Copies Value When Only Index Needed |
| PERF-130 | Unnecessary Function Wrapper Adding Call Overhead |
| PERF-131 | sync.Mutex Used Where sync/atomic Suffices |
| PERF-132 | Goroutine Spawned Without Context Propagation |
| PERF-133 | sort.Slice Closure Allocation Inside Loop |
| PERF-134 | Manual io.Read/Write Loop Instead Of io.Copy |
| PERF-135 | encoding/gob Encoder Or Decoder Not Reused |
| PERF-136 | filepath.Join Repeatedly Called With Same Base |
| PERF-137 | runtime.Caller Used In Hot Path |
| PERF-138 | runtime.Stack Used In Hot Path |
| PERF-139 | Closure Allocates Due To Variable Escape |
| PERF-140 | debug.SetGCPercent Misuse Or Tuning In Production |
| PERF-141 | URL.Query() Called Repeatedly Without Caching |
| PERF-142 | http.MaxBytesReader Not Used For Untrusted Body |
| PERF-143 | http.TimeoutHandler Not Used For Route-Level Timeouts |
| PERF-144 | Content-Length Not Set In HTTP Response |
| PERF-145 | http.Request.WithContext Allocation On Hot Path |
| PERF-146 | fmt.Sprintf With Single String And No Verbs |
| PERF-147 | strings.Replace Call Where ReplaceAll Suffices |
| PERF-148 | Goroutine Leak Via Channel Send Without Guaranteed Receiver |
| PERF-149 | net.Conn Deadlines Not Set For Network Operations |
| PERF-150 | Large Stack Frame From Local Variables |
| PERF-151 | Non-Inlinable Function On Hot Path Due To Complexity |
| PERF-152 | Header Copy Via Manual Loop Instead Of Clone |
| PERF-153 | http.Cookie.String Called Repeatedly |
| PERF-154 | Unnecessary http.HandlerFunc Type Conversion |
| PERF-155 | http.ServeMux Pattern Without Method Restriction |
| PERF-156 | Ranging Over String With Only Index Usage |
| PERF-157 | Unnecessary Use Of fmt.Sprint With Single String |
| PERF-158 | Sorting Slice Of Basic Types With Closure |
| PERF-159 | Using json.NewDecoder Instead Of json.Unmarshal For Buffered Data |
| PERF-160 | sql.Open Inside Request Handler |
| PERF-161 | rows.Err Not Checked After Iteration |
| PERF-162 | db.Ping Inside Request Handler |
| PERF-163 | db.Query Instead Of QueryRow For Single Row |
| PERF-164 | Missing Context In Database Calls |
| PERF-165 | Not Implementing sql.Scanner For Custom Types |
| PERF-166 | database/sql Null Handling Without sql.Null Types |
| PERF-167 | WaitGroup.Add Inside Goroutine |
| PERF-168 | Large Struct Sent By Value Over Channel |
| PERF-169 | atomic.Value Frequent Store Allocation |
| PERF-170 | sync.Once In Hot Function Path |
| PERF-171 | Channel Used As Mutex |
| PERF-172 | WaitGroup.Wait Blocking Serving Goroutine |
| PERF-173 | time.Tick Not Stopped Causing Goroutine Leak |
| PERF-174 | Closing Channel By Receiver |
| PERF-175 | Buffered Channel Spinning On Receive |
| PERF-176 | io.Copy Without Buffer Reuse |
| PERF-177 | os.File.Readdir Instead Of os.ReadDir |
| PERF-178 | time.Format Instead Of time.AppendFormat |
| PERF-179 | strings.Replacer Not Used For Repeated Replace |
| PERF-180 | encoding/csv Reader Per Row |
| PERF-181 | json.Decoder UseNumber Missing |
| PERF-182 | bufio.Writer Default Buffer Undersized |
| PERF-183 | context.WithTimeout Inside Loop |
| PERF-184 | mime.TypeByExtension In Hot Path |
| PERF-185 | http.DetectContentType In Request Handler |
| PERF-186 | strings.Fields In Hot Parsing Path |
| PERF-187 | template.HTMLEscaper In Hot Path |
| PERF-188 | fmt.Sscanf In Hot Path |
| PERF-189 | HTTP Response Body Not Drained Before Close |
| PERF-190 | HTTP Client Missing Timeout |
| PERF-191 | Slice Of Pointers For Small Structs |
| PERF-192 | Map Without Size Hint |
| PERF-193 | Not Resetting Timer In Loop |
| PERF-194 | Using time.Sleep For Polling |
| PERF-195 | log.Fatal Or log.Panic In Goroutine |
| PERF-196 | JWT Token Parsing Per Handler |
| PERF-197 | Multiple io.ReadAll On Request Body |
| PERF-198 | Content-Type Check With strings.Contains |
| PERF-199 | Session Store Lookup Per Handler |
| PERF-200 | Middleware Ordering Penalty |
| PERF-201 | CORS Preflight Handler Allocation |
| PERF-202 | json.Marshal Indent In Production Handler |
| PERF-203 | net.IP.String Repeated In Hot Path |
| PERF-204 | GORM Updates With Map Without Select |
| PERF-205 | GORM Pagination Without Count Optimization |
| PERF-206 | sqlx Unsafe Without Known Input |
| PERF-207 | Fiber ctx.SendFile Without Caching |
| PERF-208 | Prometheus Counter Without Bounded Label Set |
| PERF-209 | Cobra PersistentPreRun In Every Command |
| PERF-210 | go-redis KEYS Command In Application Code |
| PERF-211 | GORM Not In Select Clause |
| PERF-212 | GORM Find Without Limit On Large Table |
