# grpc-claim-audit

Version 0.1.0. An offline, standard-library audit of documented remote-procedure-call interface claims against Python source. Source is parsed, never imported or executed.

Install and run:

```sh
python3 -m pip install .
grpc-claim-audit .
python3 -m grpc_claim_audit . --json
python3 -m unittest discover
python3 -m build
```

The positional argument is a readable project directory. Options: `--json` emits structured results; `--verbose` lists evidence and parse/read diagnostics; repeatable `--ignore GLOB` excludes root-relative paths; `--fail-on HIGH` is the default, while `--fail-on MEDIUM` also fails on test-only evidence. `--version` prints 0.1.0.

Exit status is 0 for PASS, 2 for findings meeting the threshold, and 1 for invalid usage or an unreadable root. JSON includes `verdict`, `findings` (rule, severity, message), `evidence`, and `errors`. A positive claim lacking production evidence receives HIGH, or MEDIUM when evidence exists only in tests. A negative claim contradicted by production evidence receives HIGH. There is at most one finding per claim family.

## Limitations

Only a fixed vocabulary of affirmative and negative transport templates counts. Bare protocol nouns, package names, dependency lists, REST/JSON, webhooks, websockets, server-sent events, GraphQL, and query filtering do not count. Matching is case-insensitive, expands contracted negation, replaces hyphens with spaces, and joins whitespace within paragraphs. Negative spans are removed before affirmative matching. Root README.md and Markdown beneath any docs path component are checked; fenced blocks are excluded and inline code counts.

Evidence requires a library-resolved server constructor plus a servicer registration helper in the same module, or a library-resolved channel constructor plus an imported generated stub instantiation in the same module. Aliases and asynchronous constructors count. Local stub definitions, imports alone, strings, comments, decorators, raw sockets, and individual halves of either pair do not establish evidence. These syntactic fingerprints cannot prove runtime behavior, reachability, correct registration, or successful network calls.

Production scanning excludes tests, test-named files, fixtures, docs, examples, and symlinked files or directories. Test evidence is assessed separately. Ignore patterns use root-relative shell-style matching. Environment files are never opened. Malformed or unreadable candidate files are reported as diagnostics and provide no evidence. With no source, an affirmative claim fails and a negative claim passes. No recognized claim means PASS regardless of source.

MIT licensed. No runtime dependencies.
