# Context Rot, Compaction, and Verified Handoff

**Research date:** 2026-08-09

**Scope:** Empirical long-context degradation, operational meaning of a reported approximately 200,000-token boundary, current OpenAI/Codex, Anthropic/Claude Code, Google Gemini, OpenClaw, and Hermes continuity capabilities, and feasibility of an automatic verified handoff.

**Status:** Evidence review, not provider certification. No live end-to-end provider transition was executed for this report.

**Evidence labels:** **Paper** means an original research paper; **first-party documentation** means current product documentation; **first-party source** means repository source pinned to the cited commit; **engineering report** means a reproducible but non-peer-reviewed technical report; **inference** means a design conclusion derived from cited evidence; **unknown** marks an evidence gap.

## Verdict

Long-context capacity is not reliable usable context. Peer-reviewed evaluations show degradation from evidence position, distractors, semantic mismatch, task type, and multi-session history well before nominal context limits. Lost in the Middle found that relevant information at the beginning or end of a long input was used more reliably than the same information in the middle.[5] RULER found that nearly perfect vanilla needle-in-a-haystack performance coexisted with large degradation on more complex long-context tasks and that only half of evaluated models maintained its qualitative 32K threshold despite every evaluated model claiming at least 32K capacity.[6] HELMET found, across 59 long-context models and seven application-oriented categories, that synthetic retrieval tasks did not reliably predict downstream performance and that task categories had distinct, weakly correlated behavior.[7]

The reported approximately 200,000-token observation is credible as an operational boundary, but not as a universal onset of context rot. OpenAI documentation uses `compact_threshold: 200000` in an automatic-compaction example; the value is caller-selected, not documented as a universal quality threshold.[2] Claude Code documents a 200K automatic-compaction boundary for several specific 200K-window configurations, while other models and deployment modes use different limits.[16] Hermes exposes a default `codex_responses_compact_threshold` of 200,000 tokens for its opt-in native OpenAI Responses path.[25] These convergent values explain why 200K can appear repeatedly in practice, but they are product heuristics or capacity-management choices, not evidence that quality remains stable until 200K.

An automatic, fail-closed handoff safeguard is technically feasible, provided it is implemented outside model-generated prose. Codex exposes blocking `PreCompact` and `PostCompact` continuation controls, a `SessionStart` source for post-compaction re-entry, and `SubagentStop` continuation control.[21] Anthropic's Messages API can pause immediately after producing a compaction block, creating a client-controlled verification point before generation resumes.[13] Claude Code can block `PreCompact` and `SubagentStop`, although `PostCompact` is observational rather than blocking.[15] These surfaces can enforce an adapter sequence of canonical checkpoint, transition, rehydration, deterministic comparison, and continue-or-block. They do not themselves prove semantic continuity.

No evidence supports a universal claim that one safeguard can preserve “at least 90%” of context, task quality, or intent across all providers and workloads. The population, workload, metric, model and version, number of transitions, and confidence bound are undefined. For authority, invariants, blockers, acceptance criteria, and exact identifiers, a 90% aggregate target is also the wrong safety objective: any observed protected-field loss must block the transition. A 90% lower-bound target can be meaningful only for a separately defined aggregate task-success metric on held-out, workload-stratified evaluations.

The existing 50% checkpoint, 65% transition, and 75% refusal policy, together with any corresponding absolute 80K, 120K, or 160K ceilings, must therefore be labeled `PROVISIONAL_UNCALIBRATED`. The evidence directly contradicts treating 80K as a universally early safe boundary: NoLiMa found severe degradation at 32K, and some conditions degrade at still shorter lengths.[8] It contradicts treating 120K as reliably usable for multi-session work: LongMemEval found 30% to 60% declines at approximately 115K tokens relative to oracle evidence-only context.[9] It provides no basis for treating 160K as a quality ceiling. Conversely, first-party Gemini documentation reports very high performance on some single-query retrieval cases at much longer context, so the absolute ceilings may be unnecessarily conservative for simple workloads.[17] Thresholds must be calibrated by model, harness, workload, tool-output profile, and transition mechanism.

## Definitions and Scope

**Context window capacity** is the maximum information a model can consider in one request, not a guarantee that every token is used with equal fidelity.[3] **Context utilization** is the measured or conservatively bounded input-token count divided by the actual capacity for the active provider, model, route, and harness. A threshold expressed as a percentage is meaningful only when both numerator and denominator are current, attributable observations.

**Context rot**, for this report, is the measurable degradation in retrieval, reasoning, instruction adherence, abstention, or task completion as additional context is introduced while the target task remains materially the same. This is an operational definition, not a claim that a stored transcript decays over time. Chroma uses the term for non-uniform performance decline as input length grows, and Anthropic describes a performance gradient rather than a single hard cliff.[10][11]

**Context pollution** is the burial of relevant requirements and evidence under noisy intermediate output, distractors, stale turns, or irrelevant state. Codex documentation explicitly distinguishes context pollution from context rot and recommends isolated subagents to keep raw exploration and tool output out of the main thread.[4] Isolation reduces pollution; it does not prove that the summary returned from the isolated thread is complete or correct.

**Compaction** replaces or precedes older conversation content with a shorter representation so work can continue. OpenAI's compacted Responses item is opaque and intended to be replayed as returned.[2] Anthropic compaction creates a model-generated `compaction` block and discards content before the latest block on subsequent requests.[13] OpenClaw persists a compact summary in the transcript while retaining full history on disk.[22] These mechanisms differ materially and must not share an unverified assumption about what survives.

**Handoff** is a change of active context, session, process, or actor. **Verified handoff**, as used here, requires an external canonical projection of protected state before the transition, a newly observed projection after rehydration, and a deterministic comparison that passes before ordinary work resumes. A natural-language acknowledgment, compacted summary, child-agent report, or matching topic is evidence input, not acceptance.

The report evaluates context fidelity and transition enforceability. It does not claim that any cited benchmark reproduces a complete coding-agent session, that provider product defaults are optimal, or that an adapter is production-ready merely because a hook or API field exists.

## Empirical Findings

### Position alone changes performance

**Paper, peer-reviewed.** Lost in the Middle evaluated multi-document question answering and key-value retrieval while moving relevant information within the input. Performance was often highest when relevant information appeared at the beginning or end and substantially worse when it appeared in the middle; extended-context variants did not automatically use shared in-window content more effectively than shorter variants.[5] This falsifies a simple capacity model in which any fact below the nominal token limit is equally available.

The continuity implication is that a protected fact cannot be considered safe merely because it remains somewhere in the prompt. Calibration must randomize protected-field position, including middle placement, and post-transition verification must compare canonical values rather than ask the model whether it remembers them.

### Simple retrieval overstates usable context

**Paper, peer-reviewed conference version.** RULER extends vanilla needle-in-a-haystack retrieval with multiple needles, distractors, multi-hop tracing, aggregation, and question answering. Its 17-model evaluation found that almost all models suffered large degradation as length and task complexity increased even when vanilla retrieval was nearly perfect. Only half sustained the paper's qualitative performance threshold at 32K, and almost all crossed below that threshold before their claimed maximum length.[6]

**Paper.** HELMET evaluates application-oriented tasks through 128K tokens. Across 59 models, it found that no synthetic task achieved an average rank correlation above 0.8 with downstream categories, that original needle-in-a-haystack correlations were weak, and that capabilities such as summarization, in-context learning, retrieval, reranking, and citation generation did not consistently correlate.[7] A single synthetic retrieval gate therefore cannot certify a handoff system that must preserve authority, follow instructions, reason over updates, and use tools.

These results cut both ways. They reject claims based only on nominal capacity or vanilla needle retrieval, but they also reject a single universal utilization threshold. A model may remain strong on literal retrieval while failing on aggregation or instruction following at the same length; another may show a different task ordering.

### Semantic mismatch causes early failure

**Paper, peer-reviewed.** NoLiMa removes the literal lexical overlap between questions and relevant facts. It evaluated 13 models advertised with at least 128K context. At 32K, 11 models fell below 50% of their strong short-context baselines; GPT-4o declined from 99.3% to 69.7%.[8] The important operational result is not one model ranking but that semantic association turns a seemingly easy retrieval problem into a failure well below 80K.

NoLiMa also reports degradation curves beginning before 32K rather than a single onset at the advertised limit.[8] Therefore a policy that first intervenes at 80K cannot be called conservative for all semantic-retrieval workloads. This is the strongest direct contradiction of a universal 80K safety ceiling in the reviewed literature.

### Multi-session history is materially harder than oracle evidence

**Paper, peer-reviewed.** LongMemEval constructs realistic user-assistant histories containing information extraction, temporal reasoning, knowledge updates, and abstention. Its standard long-context setting is approximately 115K tokens. Four evaluated long-context models showed a 30% to 60% decline when reading the full history compared with an oracle condition containing only evidence sessions, regardless of whether a chain-of-note technique was used.[9]

This result is directly relevant to agent continuity because old and updated facts, distractor sessions, and temporal relationships resemble a working agent transcript more closely than a single needle. It contradicts treating 120K as a generally safe point for unverified continuation. It also supports evidence selection and canonical state projection: the oracle evidence-only condition was substantially easier than replaying the complete history.

### Controlled engineering evidence isolates length effects

**Engineering report, non-peer-reviewed.** Chroma evaluated 18 models on controlled tasks designed to hold task difficulty constant while varying irrelevant input length. It reports eight input lengths, 11 needle positions for its needle experiments, and 194,480 total model calls. Across its experiments, performance generally degraded with length; lower needle-question similarity and distractors amplified decline, and changing haystack structure affected results.[10]

Chroma's strongest contribution is the length-only control: when the same needle-question pair is held fixed and only irrelevant content grows, performance still declines.[10] Its limitations are also material. It is a vendor engineering report, includes a model-based judge, mixes model families and modes, and does not measure protected authority continuity. It corroborates the peer-reviewed direction of effect but does not establish a production threshold.

### Empirical synthesis

The combined evidence supports a gradient, not a cliff.
Position effects show that location matters.[5]
RULER and HELMET show that task complexity and benchmark choice matter.[6][7]
NoLiMa shows that lexical versus semantic matching matters.[8]
LongMemEval shows that multi-session distractors, updates, and temporal structure matter.[9]
Chroma shows that length itself can matter even when task content is controlled.[10]

Accordingly, “usable context” is a property of the tuple `(provider, model/version, route, harness, prompt, workload class, tool-output profile, transition count)`. A context-window number is only a capacity constraint. A product compaction default is only an engineering policy. Neither substitutes for workload-specific behavioral evidence.

## Assessment of the Approximately 200,000-Token Observation

The observation is plausible for at least three independent product reasons. OpenAI's official compaction guide demonstrates automatic server-side compaction with a caller-specified threshold of 200,000 tokens and also exposes a standalone compact endpoint.[2] Claude Code documents automatic compaction at the 200K boundary for Sonnet 4.6 and Opus 4.6 without extended context and for later Opus models when deployed with a 200K context window.[16] Hermes sets 200,000 as the default native Responses compaction trigger in its documented configuration.[25]

None of those sources says that quality is uniform through 200K. OpenAI labels the threshold as configuration and describes the resulting item as opaque.[2] Claude Code explicitly warns that early detailed instructions can be lost during automatic compaction and directs persistent rules into `CLAUDE.md` instead of conversation history.[14] Hermes' own general compressor defaults to 50% and separately uses an 85% gateway safety net, per-model overrides, small-context floors, and special route behavior, demonstrating that one numeric boundary does not govern all paths.[25]

Other first-party defaults contradict 200K as a universal operational threshold. Anthropic's server-side API compaction defaults to 150,000 input tokens and allows a minimum configured trigger of 50,000.[13] The pinned Gemini CLI source triggers compression at 50% of the active model limit and retains the recent 30% of history.[20] Claude Code also supports user-selected automatic-compaction windows from 100K to 1M subject to the model limit.[16]

**Inference.** Approximately 200K is best interpreted as a recurring capacity-management boundary in particular current products and routes. It is not evidence of a common cognitive phase transition. If a local session became unreliable near 200K, the observation should be retained as a reproducible local signal and used to seed calibration, while lower utilization bins remain mandatory because controlled studies show earlier failures.

## Current Product Capabilities

### OpenAI Responses API and Codex

**First-party documentation.** The Responses API supports stateless manual replay and server-managed continuation through response or conversation state.[1] Its compaction guide supports automatic threshold compaction and a standalone compact endpoint. The compacted output is opaque, must not be pruned, and is intended to be supplied to a later request.[2] This provides a transport mechanism, not an inspectable fidelity proof.

**First-party documentation.** Codex subagents execute in separate threads and return summaries to the main chat. Codex documentation describes this as a way to keep noisy intermediate output out of the main context and explicitly notes that long chats can become less reliable.[4] It does not promise that the returned summary preserves every requirement, blocker, decision, identifier, or evidence relationship.

**First-party documentation.** Codex hooks provide enforceable lifecycle points. `PreCompact` can stop before compaction; `PostCompact` can stop after compaction; `SessionStart` with source `compact` runs before the next model request, including automatic mid-turn continuation; and `SubagentStop` can continue or stop the child flow.[21] This is the strongest reviewed harness surface for inserting a deterministic continuity adapter without patching the application bundle.

**Capability verdict.** OpenAI/Codex can support automatic verified transitions if canonical protected state lives outside the opaque compacted item and the hooks call a deterministic adapter. Hook registration alone is configuration evidence. A live test must prove that a failing comparison prevents the next ordinary model request.

### Anthropic Messages API and Claude Code

**First-party documentation.** Anthropic's server-side compaction summarizes older messages into a `compaction` block and drops content before the latest block on subsequent requests. Its default trigger is 150,000 input tokens. `pause_after_compaction` returns immediately after summary creation, allowing the client to add content or perform a verification step before continuing.[13]

**First-party engineering guidance.** Anthropic describes context as a finite resource with diminishing marginal returns, recommends compaction, structured note-taking, and subagent architectures, and warns that overly aggressive compaction can lose subtle but critical context.[11] Its long-running-agent harness report says compaction alone is insufficient and uses durable progress artifacts and feature state across clean sessions.[12]

**First-party documentation.** Claude Code states that early detailed instructions may be lost as context fills and after summarization, while root `CLAUDE.md` and unscoped rules are re-injected from disk.[14][16] Its hook reference shows that `PreCompact` and `SubagentStop` can block, while `PostCompact` cannot block and is suitable only for observation or side effects.[15]

**Capability verdict.** Anthropic's API pause is a clean enforcement point for an external compare-before-continue gate. Claude Code can prevent compaction before a checkpoint exists and can prevent a subagent from stopping before required evidence is returned. Post-compaction verification must either use a subsequent blocking control or be enforced by the client wrapper because `PostCompact` itself is non-blocking.

### Google Gemini API and Gemini CLI

**First-party documentation.** Gemini's long-context guide advertises million-token windows but acknowledges that multiple-needle retrieval does not maintain the same accuracy as a single needle and that performance varies widely with context. It recommends placing the query at the end of a long prompt. Context caching is presented as a cost and latency optimization, not as a fidelity safeguard.[17]

**First-party documentation.** The Gemini Interactions API can continue conversation history through `previous_interaction_id`, but interaction-scoped parameters such as tools, system instructions, and generation configuration must be re-specified on each interaction.[18] A handoff adapter must therefore verify both retained history and current execution configuration; a server-side conversation identifier alone is insufficient.

**First-party documentation and pinned source.** Gemini CLI's `PreCompress` hook is asynchronous and advisory only; it cannot block or modify compression.[19] At pinned commit `cf22ac7e86f3dcf528e3ae591fec1c03090a49f8`, the compressor triggers at 50% by default, preserves the latest 30%, caps preserved function-response tokens, asks a second model pass to identify omitted technical details and constraints, and rejects a result whose token count exceeds the original.[20]

**Capability verdict.** Gemini CLI contains useful self-review and size gates, but its compression hook cannot enforce canonical checkpoint-before-compress. A verified handoff requires a wrapper that intervenes before the CLI reaches its compression trigger or a separate stop/restart boundary controlled by the adapter. Model self-review remains maker review, not independent deterministic comparison.

### OpenClaw

**First-party documentation.** OpenClaw compacts old turns into a summary stored in the session transcript, keeps recent messages intact, retains the full conversation on disk, and supports memory flush before compaction. It exposes pluggable compaction providers and a context-engine successor-session seam.[22] These are useful integration points for an external continuity guard.

**Pinned first-party source.** At commit `1471881af7aaff047c605dce08caa9a86f0de316`, OpenClaw's compaction safeguard requires five summary headings, checks overlap with the latest ask, and checks at most 12 extracted opaque identifiers. Latest-ask matching uses at most 12 tokens and requires only one or two token matches depending on the ask.[23] These checks catch malformed summaries and some literal omissions, but they do not establish semantic equivalence, canonical authority, evidence freshness, or complete protected-state retention.

**First-party documentation.** OpenClaw subagents run in isolated sessions by default, can optionally fork parent context, and return a result to the requester. Its completion metadata instructs the parent to verify the child result before deciding whether the original task is complete.[24] The runtime guidance correctly treats child output as evidence for synthesis, not as proof.

**Capability verdict.** OpenClaw has the required persistence and extension seams for integration, but its current safeguard audit is heuristic. Production continuity would require a canonical protected projection and a fail-closed comparison layered around, not inferred from, the summary quality check.

### Hermes

**First-party documentation.** Hermes documents a pluggable context engine, a default 50% in-loop compressor, an 85% gateway safety net, model-specific thresholds, structured summaries, stable in-place session IDs, and an optional native OpenAI Responses threshold of 200,000 tokens.[25] Its multiplicity of routes and thresholds reinforces that threshold policy belongs to a calibrated adapter profile.

**Pinned first-party source.** At commit `2446c8bb6755ff5e6feff4d26e425661edd4019b`, the compressor supports a deterministic bounded fallback summary when configured to continue after ordinary summary failure, and a fail-closed abort that returns original messages unchanged when `abort_on_summary_failure` is enabled. Authentication, access/quota, and network failure classes always abort rather than silently dropping the middle window.[26]

**Pinned first-party source.** Hermes' public subagent lifecycle binds a handle to the active parent session, computes a SHA-256 hash over the terminal result, and exposes immutable dataclasses. Running children and completed results are held in process; reconnect returns `RECONNECT_UNAVAILABLE` when a serialized handle cannot be resolved after process restart.[27] The hash protects result identity after creation, not semantic completeness, and process-restart continuity remains an explicit limitation.

**Capability verdict.** Hermes supplies strong deterministic failure behavior and useful provenance primitives, but an immutable result hash cannot show that the result retained the right facts. Restart-safe canonical transition state must live outside the in-process lifecycle registry.

## Automatic Handoff Feasibility

**Inference: feasible architecture.** An enforcing adapter can observe attributed token usage, turn count, phase changes, and tool-output spikes; freeze a canonical protected projection; prepare a transition bound to the current checkpoint and actor; invoke provider compaction, restart, or isolated handoff; reconstruct a fresh projection from canonical records; compare exact protected identities and digests; then either release ordinary continuation or return `BLOCK`. This sequence does not require access to hidden reasoning and does not trust a generated summary.

The protected projection should include goal, acceptance criteria, invariants, authority, accepted decisions, current evidence identities and freshness, unresolved questions, open assignments, exact blockers, failure fingerprint, next action, work-scope lineage, active provider/model/route identity, tool schema identity, and the transition target. Narrative explanations can accompany these records but cannot create, remove, or broaden them.

The adapter must treat provider capabilities differently.
OpenAI Responses compaction is opaque, so verification occurs against external canonical records after replay, not by inspecting the compacted item.[2]
Codex hooks can stop both sides of compaction.[21]
Anthropic's `pause_after_compaction` supplies an API-level verification pause.[13]
Claude Code can block before compaction but needs wrapper enforcement after compaction because its post hook cannot block.[15]
Gemini CLI's advisory-only pre-compression hook cannot be the enforcement point.[19]
OpenClaw and Hermes expose extension seams, but their summary and result checks remain inputs to the external comparison.[22][26][27]

Automatic subagent handoff is feasible under the same rule. A clean context reduces pollution, but only a destination-generated projection compared with canonical source records constitutes acceptance. The parent must not equate a child summary, child result hash, success status, or “I understand” acknowledgment with continuity.[4][24][27]

The safe online trigger is the minimum of several independently calibrated boundaries: token utilization, turn cap, task-phase boundary, high-risk decision, large tool-output spike, and explicit handoff or restart. A transition may occur early even when token utilization is low, and it may remain unnecessary for a simple task at a length where a complex semantic task already fails. Output-token and tool-call reserve must be subtracted before comparing against any input ceiling.

## Universal 90% Claim

“90% preserved” has no testable meaning until the preserved object and denominator are declared. It could mean exact protected-field retention, semantic fact recall, task success, instruction adherence, judge score, or proportion of sessions without a critical failure. Those metrics are not interchangeable, as HELMET's low cross-category correlations demonstrate.[7]

For canonical authority and invariants, the required gate is exact equality and zero observed loss. A single removed blocker, broadened permission, changed goal, stale evidence substitution, or altered next action makes the transition fail regardless of aggregate recall. This is a deterministic conformance requirement, not a statistical 90% target.

For aggregate task success, a 90% claim must specify a held-out population and confidence method. As an illustration, if all trials succeed, at least 29 independent trials are needed for a one-sided exact 95% lower confidence bound to exceed 90%; a two-sided 95% interval requires at least 36 all-success trials. That calculation applies per claimed stratum, not to a pooled mixture that can hide failure on rare high-risk workloads. Dependence between repeated transitions, shared prompts, or reused traces reduces the effective sample size and must be modeled or removed.

No reviewed source evaluates a single handoff safeguard across every listed provider, current model version, harness, workload, tool profile, and repeated-compaction depth. Therefore the universal claim is unsupported. A defensible statement would be narrower: for a frozen adapter profile and declared workload stratum, exact protected fields showed zero observed loss, and held-out task success met a predeclared lower confidence bound.

## Calibration Strategy

Calibration must freeze a profile keyed by provider, exact model and version, route, harness build, system and compaction prompts, tokenizer or provider usage source, tool schema set, workload class, and transition mechanism. Any change to those fields invalidates or narrows prior evidence. Model-family names and nominal context sizes are insufficient identities.

The replay corpus should exercise utilization bins such as 10%, 25%, 40%, 50%, 60%, 70%, 80%, and 90% of observed capacity, while reserving space for output and tools. Absolute 80K, 120K, 160K, and 200K points should be included when supported by the active route because they are operationally salient, but they must not replace percentage bins or lower-length probes.

At each bin, randomize protected facts across beginning, middle, and end positions; inject irrelevant material and hard distractors; vary lexical and semantic similarity; require multi-hop reasoning, aggregation, knowledge updates, temporal ordering, abstention, and tool use; and test noisy or oversized tool output.
Position, complexity, and semantic-mismatch studies support these dimensions.[5][6][8]
The corpus should include both long single requests and multi-turn histories because multi-session and length-controlled studies expose additional failure modes.[9][10]

Every trace should run in four conditions: short oracle evidence only, full uncompressed history, native compaction or handoff, and guarded transition with canonical rehydration. Repeat guarded transitions at increasing depth to expose cumulative summary drift. Use deterministic protected-field checks before model judging, then score task correctness, unauthorized broadening, blocker preservation, evidence freshness, abstention, latency, cost, and number of rehydration attempts.

Threshold selection should use a predeclared non-inferiority margin against the short oracle baseline for each workload class. Select the operational transition threshold below the first statistically meaningful non-inferiority failure, then subtract a measured output/tool reserve. The checkpoint threshold must precede transition by enough turns and tokens to persist a canonical record under worst observed growth. The refusal threshold must precede the provider hard limit by enough reserve to execute checkpoint and transition recovery.

The current 50%/65%/75% policy is a reasonable conservative experimental seed because it creates space between observation, transition, and refusal. It is not empirically optimal. NoLiMa and RULER require lower probes because failures occur by 32K.[6][8] Gemini single-query retrieval and some million-token models require higher probes to avoid needlessly constraining simple tasks.[17] Calibration should be allowed to move thresholds in either direction per frozen profile.

Recalibration is mandatory after a model, provider route, context size, harness version, compaction prompt, hook behavior, tool schema, system instruction, workload distribution, or tokenizer/usage source changes. Online monitoring should record drift separately from the offline calibration corpus; production traces must not silently become training or threshold-selection data.

## Evidence Gates

**Source gate.** Every material product claim must resolve to current first-party documentation or pinned first-party source; every empirical threshold claim must resolve to an original paper or explicitly labeled engineering report. Pass requires URL resolution, source-to-claim review, and recorded access date. A search snippet is insufficient.

**Metric gate.** The adapter must receive provider- or harness-attributed capacity and a complete conservative used-token upper bound with observation time. Pass requires current route identity, freshness within policy, integer units, and reserved output/tool budget. Missing, stale, estimated-without-bound, or route-mismatched usage is `UNKNOWN` and cannot authorize ordinary continuation at a protected boundary.

**Pre-transition gate.** Pass requires an atomically persisted canonical checkpoint and protected projection bound to the current goal, authority, actor, evidence head, target, policy, and transition kind. A generated summary or transcript alone fails.

**Post-transition gate.** Pass requires a fresh destination projection and exact equality for all protected identities and digests, complete required evidence, no authority broadening, preserved blockers and assignments, and current evidence after normal invalidation. Narrative similarity, topic overlap, acknowledgment, summary headings, or identifier sampling cannot pass this gate.

**Behavioral enforcement gate.** Pass requires a live test in which an intentionally incomplete or altered projection prevents the next ordinary model/tool action on the actual provider adapter. Hook registration, configuration presence, unit tests, and API documentation are necessary but not sufficient.

**Calibration gate.** Pass requires held-out, workload-stratified replay across utilization bins and repeated transitions; zero protected-field loss; a predeclared non-inferiority comparator; and the declared confidence bound for aggregate task success. A pooled average cannot mask a failing workload stratum.

**Failure-injection gate.** Pass requires demonstrated refusal on missing authority, changed invariant, removed blocker, stale evidence, changed next action, wrong actor or target, truncated identifier set, summary injection, and repeated identical rehydration failure. Recovery attempts must be distinct and bounded.

**Release gate.** Pass requires provider/model/harness identity, raw test evidence, current hook or pause behavior, rollback path, and an explicit statement of which provider profiles remain untested. Until the behavioral enforcement and calibration gates pass, the correct verdict is `NOT_CALIBRATED`, not “90% safe” or production-ready.

## Unknowns and Limitations

**Unknown:** No reviewed study measures exact preservation of an external canonical authority projection across repeated compactions in a real coding-agent harness. Existing academic benchmarks measure related retrieval, reasoning, summarization, or memory capabilities, not this guard's full contract.

**Unknown:** No universal onset token count exists in the evidence.
Position, benchmark design, and semantic similarity change the observed curves.[5][7][8]
Task complexity, multi-session history, and controlled input growth change them further.[6][9][10]

**Unknown:** Product documentation establishes intended behavior, not live behavior on this Mac or a specific account and route. Codex, Claude Code, Gemini CLI, OpenClaw, and Hermes hook or compression surfaces may change after the cited versions. Pinned source establishes code content at one commit, not deployed-process identity.

Academic benchmarks also have external-validity limits.
Lost in the Middle and RULER include synthetic components.[5][6]
HELMET improves task breadth but still uses benchmark datasets and model-based evaluation in some categories.[7]
NoLiMa isolates semantic retrieval rather than full agent work.[8]
LongMemEval is closer to multi-session use but uses constructed histories.[9]
Chroma is non-peer-reviewed and uses a model judge.[10]

Token counts are not fully portable. Providers tokenize differently, some report input after internal transformations, opaque compacted items may not expose semantic size, and cached or server-managed state can change billed tokens without changing information presented to the model. Calibration must use the actual adapter observation and retain uncertainty rather than translate model names into assumed capacity.

External state can improve continuity beyond what a transcript benchmark measures. Canonical files, databases, commits, tests, and evidence stores can rehydrate facts on demand. They can also introduce stale or conflicting state. The guard must verify identity and freshness rather than assume that retrieval from disk is correct.

This report did not run private production traces, inspect secret-bearing transcripts, or execute a natural multi-provider handoff. It therefore supports architecture and calibration design, not a claim that any adapter currently passes the behavioral enforcement gate.

## Methodology and Source Handling

Research used two evidence cycles. The empirical cycle began with long-context benchmark landscape review, then targeted position effects, synthetic-versus-downstream validity, semantic mismatch, multi-session history, and length-only controls. The product cycle began with official compaction and context documentation, then inspected current hook semantics and source-pinned compressor or lifecycle implementations where documentation alone could not establish enforcement behavior.

Source priority was original peer-reviewed papers, first-party product documentation, and source pinned to exact commits. Chroma is retained as an explicitly non-peer-reviewed engineering report because it publishes methods, call counts, and a reproducible codebase; it is corroborative rather than threshold authority.[10] Vendor engineering guidance is treated as product experience, not independent empirical validation.[11][12]

Every URL below was registered in the task citation ledger before drafting. Inline numeric citations map mechanically to that ledger. Citation verification must reject unknown identifiers or a Sources block that differs from the ledger. All 27 sources were accessed on **2026-08-09**.

## Sources

[1] https://developers.openai.com/api/docs/guides/conversation-state — OpenAI conversation state
[2] https://developers.openai.com/api/docs/guides/compaction — OpenAI compaction
[3] https://learn.chatgpt.com/docs/glossary — OpenAI Codex glossary
[4] https://learn.chatgpt.com/codex/agent-configuration/subagents — OpenAI Codex subagents
[5] https://aclanthology.org/2024.tacl-1.9 — Lost in the Middle (TACL 2024)
[6] https://arxiv.org/abs/2404.06654 — RULER
[7] https://arxiv.org/abs/2410.02694 — HELMET
[8] https://proceedings.mlr.press/v267/modarressi25a.html — NoLiMa (ICML 2025)
[9] https://proceedings.iclr.cc/paper_files/paper/2025/file/d813d324dbf0598bbdc9c8e79740ed01-Paper-Conference.pdf — LongMemEval (ICLR 2025)
[10] https://research.trychroma.com/context-rot — Chroma Context Rot report
[11] https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents — Anthropic context engineering
[12] https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents — Anthropic long-running agents harness
[13] https://platform.claude.com/docs/en/build-with-claude/compaction — Anthropic compaction docs
[14] https://code.claude.com/docs/en/how-claude-code-works — Claude Code mechanics
[15] https://code.claude.com/docs/en/hooks — Claude Code hooks
[16] https://code.claude.com/docs/en/context-window — Claude Code context window
[17] https://ai.google.dev/gemini-api/docs/long-context — Gemini API long context
[18] https://ai.google.dev/gemini-api/docs/interactions/interactions-overview — Gemini Interactions API
[19] https://geminicli.com/docs/hooks/reference — Gemini CLI hooks
[20] https://github.com/google-gemini/gemini-cli/blob/cf22ac7e86f3dcf528e3ae591fec1c03090a49f8/packages/core/src/context/chatCompressionService.ts — Gemini CLI compression source
[21] https://learn.chatgpt.com/codex/hooks — Codex hooks
[22] https://docs.openclaw.ai/concepts/compaction — OpenClaw compaction
[23] https://github.com/openclaw/openclaw/blob/1471881af7aaff047c605dce08caa9a86f0de316/src/agents/agent-hooks/compaction-safeguard-quality.ts — OpenClaw safeguard source
[24] https://docs.openclaw.ai/tools/subagents — OpenClaw subagents
[25] https://hermes-agent.nousresearch.com/docs/developer-guide/context-compression-and-caching — Hermes context compression
[26] https://github.com/NousResearch/hermes-agent/blob/2446c8bb6755ff5e6feff4d26e425661edd4019b/agent/context_compressor.py — Hermes compressor source
[27] https://github.com/NousResearch/hermes-agent/blob/2446c8bb6755ff5e6feff4d26e425661edd4019b/agent/subagent_lifecycle.py — Hermes subagent lifecycle source
