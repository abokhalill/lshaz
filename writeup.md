Six months ago, I introduced a static analysis tool called lshaz, which was supposed to be a “micro-architectural performance hazard” detector. 

I’ll be incredibly candid: it was not even close. 

The sheer amount of feedback I got highlighting the false positive rate was, frankly, embarrassing. The tool continuously flagged code that looked correct, and in fact was, perfectly optimized. Or in other cases, where there was a performance inefficiency, but one that was not worth the memory footprint. 

So the tool could identify structures that could interact badly with hardware, but it could not make out whether any of it was actually significant. Was the relevant memory actually shared across threads? Were the accesses occurring at a sufficient frequency to matter? And ultimately is the proposed fix actually worth implementing?

In this blog, we will delve into the complete architectural overhauls the tool went through, what changed, why it changed, and how we managed to reduce both false positive and, more crucially, false negative rates. 

This time however, we’re taking no chances. All findings the tool emits were verified by perf measurements. 


## Act 1: how it was built

To understand what was so wrong with the tool, we need to look at how it was built. Originally, the idea was dead simple: 

Take a translation unit, walk the AST, look for patterns that are known to interact badly with the hardware and record the finding. That’s literally it. 

Now at first glance, this approach doesn’t necessarily look all that defective, nor is it inherently wrong. In fact, this was considered reasonable enough at first that we thought it was ready to be used against open source software. However, as we will soon find out, this would prove to be substantially shortsighted. 

### Problem 1: one file at a time

The first major issue with this approach is that it relied on sequential translation unit pattern matching. Essentially, it parsed one TU at a time. 

In C and C++, a TU, or Translation Unit, is simply a single source file (`.c` or `.cpp`) combined with all the header files included by the preprocessor. When you compile a project, the compiler processes these TUs independently before the linker combines them into a single binary executable. 

The problem with parsing TUs one at a time was that it was simply not how hardware performance problems occur. Consider for example false sharing, where two cores keep invalidating one another’s copy of the same 64-byte line in their private L1 and L2 caches. In order for false sharing to occur, it is intuitive to guess that most of the time, the ping ponging is not going to happen inside the same single file. 

```
                     one 64-byte cache line
        |<--------------------------------------------->|

bytes   0       8       16      24      32      40      48      56    63
        +-------+-------+-------+-------+-------+-------+-------+-------+
        | head  | tail  |       |       |       |       |       |       |
        +-------+-------+-------+-------+-------+-------+-------+-------+
            ^       ^
            |       |
   producer.c       consumer.c
   writes head      writes tail

   Two different files. Two different cores. One line.
   Neither write is a bug. Together they serialize.
```

It gets even worse. If we consider a multi-threaded application, one thread might update a thread-local counter inside a struct. The tool saw and acknowledged the write operation, but it had no idea if there were other guests i.e. another thread touching that memory. If another thread say reads a flag from the same struct, the tool also saw and acknowledged the read operation, but, as you might’ve already guessed, had no idea if other threads were modifying that same cache line. 

Given this level of structural blindness, it is not that far fetched to deduce that the false positive rate would be astronomical, or that it would outright miss the whole hardware stall. 

To remedy this is to answer one question: to what extent do you need your analyzer to contextualize your source code in order to emit actionable results? That’s a fancy way of saying if it’s not per TU parsing, then what is it? The answer to that would be the complete opposite: cross-TU AND cross-thread. If microarchitectural hazards occur at the whole-program, cross-thread, and cross-file level, then the analysis engine must operate at that exact same scope. And so, that’s exactly what happened. A Map/Reduce architecture. 

Strangely enough, the design is split into two phases. The Map phase and the Reduce phase. During the Map phase, the tool parses each TU in parallel. However, and this is crucial, instead of immediately guessing whether a code pattern is a bug, it extracts lightweight, neutral facts into an intermediate representation, categorized into four data structures:

- **`EscapeSummary`**: This tracks whether a type’s memory address is passed outside its local scope, hence “escape”. 
- **`ThreadRoleSummary`**: This maps function calls, execution loops and records which functions write to or read from specific fields. The point of this is to see what each thread is doing. This gives us context on whether two independent threads are hammering at a certain cache line for example. 
- **`StripedArraySummary`**: This identifies arrays where each CPU thread is assigned its own dedicated slot to avoid lock contention. 
- **`MemorySummary`**: This collects pointer assignment constraints and unresolved memory accesses. 

These intermediate summaries are then serialized and sent over a shared IPC channel. The partial summaries are then collected from every file in the codebase and stitched back together to make up a unified global graph. Only after that, are the threshold and diagnostic rules evaluated. 

```
   MAP PHASE                             REDUCE PHASE
   one forked process per shard          parent process
   ----------------------------          --------------

   server.c     --+
   dict.c       --+   neutral    JSON       +-- merge every shard
   t_string.c   --+   facts    ---------->  +-- solve points-to
   ...          --+             over IPC    +-- build the global graph
                                            +-- apply thresholds and rules
                                                       |
                                                       v
                                                    findings

   Nothing on the left decides anything.
   Every verdict happens on the right.
```

It is immediately clear the day and night difference between the two approaches. On one hand, you are parsing each source file independently one at a time, scanning for basic infamous patterns. On the other hand, you are collecting facts on the entire source code as a whole first, and then applying your spell check.  

### Problem 2: seventeen magic numbers

We’re not out of the woods yet. To really give you a feel for just how naive this tool was; its scoring model, the one responsible for assigning the so called confidence scores for each finding, was based off on a brittle collection of 17 hand-tuned floating point weights. It attempted to calculate a “hazard probability” by nudging scores up or down based on arbitrary syntactic logic:

```
+0.10   if the IR confirmed the site survived optimization
-0.25   if the call was fully devirtualized
-0.15   if the heap allocation was eliminated
```

And seven more just to clamp the result afterwards.

It does not take a genius to conclude that the result would be an unexplainable score that meant absolutely nothing. When the tool told a developer that the statistical probability your program had false sharing was “73.2%”, you might as well have just uninstalled the thing. 

The fix here is actually not so trivial. The first thought that comes to mind naturally is to implement some sort of elegant math formula or equation that computes these values on the fly, and there is. However, there’s a critical observation to be made here, which we will go over in a second. 

## The identity crisis

Previously, if the tool saw `p->counter++` in one file and `q->counter` in another, it had zero clue if `p` and `q` pointed to the same structure. To solve this, we introduced an inclusion-based Andersen points-to solver. The point of this thing is it helps us model every single global variable, stack allocation, and heap allocation site as an abstract memory object. 

Running this against a large codebase like Redis makes the output gain crystal:

```
lshaz: [points_to] 51144 constraint(s) -> 2496 object(s);
       5892 with accesses, 90% of accesses resolved
lshaz: 172/172 TU(s) parsed, 996 diagnostic(s)
lshaz: coverage 11013 function(s), 20526 record(s), 43% hot
```

51,144 constraints collapse to 2,496 abstract objects. 5,892 of them carry
accesses, and 90% of every field access in the codebase resolves to one.


It resolves these set inclusions across all translation units. As a result, the tool collapses tens of thousands of ambiguous pointer variables into a finite set of hardware targets. This has the net effect of letting the tool know whether two writes in separate C files may land on adjacent bytes of the same 64 byte cache line. It's also worth noting that Andersen’s is a may-analysis. It computes a sound over-approximation, so it will never miss a real alias, but it can report one that never happens at runtime. 

Let me make this concrete, because this is the part that took me the longest to actually see.

Say the tool flags a possible false sharing on some struct. That reads like a single finding. It isn’t. Hiding inside it are five completely separate propositions:

- the two accesses refer to the same object
- that object is reachable from both execution roles
- the two fields genuinely land on the same cache line
- both accesses actually occur at runtime
- they occur close enough together in time to cost anything

Every one of those is its own question, with its own answer, and its own way of being wrong. And they are not even the same *kind* of question.

Some of them are load bearing. If the two accesses turn out to be different objects, there is no false sharing. Not unlikely. None. Nothing else on that list can rescue it. Others are only supporting evidence: two fields sharing a line strengthens the case, but on its own it proves nothing at all, because plenty of structs have neighbouring fields that no two threads ever touch.

The old model took all five, ran them through those weights, and handed you one number. 73.2%. That number could not tell you which of the five it was unsure about, or whether one of them had been outright disproven. A finding where we had checked nothing, and a finding where we had checked everything and found the object was thread-local, both came out somewhere in the middle.

That is the actual bug. Not the weights. The fact that a finding was one number instead of five propositions.

So the old confidence model was entirely deleted, and a finding stopped being a score. It became a ledger of claims, each one carrying its own state and its own consequence. The core function is as follows:

```
severity = min( ⋀ gating.supports ,  max( ⋁ established.supports ) )
```

Read that back with the five propositions in mind and it says something fairly ordinary. The `min` half is the load bearing ones. Every gate caps the entire finding, so the weakest one decides how far it can go. The `max` half is the supporting evidence: the strongest thing you actually established sets the level. A finding can never outrank the necessary condition it happens to be standing on.

The main reason why it isn’t your typical arithmetic over ℝ formula, is because the refutation is modal. If Refuted becomes a number near zero, then enough weakly positive evidence outvotes it. In any additive or multiplicative scheme, five signals at 0.6 beat one at 0.002. However, and this is especially worth noting, a refuted gate does not mean unlikely, it simply means never. The mechanism cannot occur. If no second core ever holds the line, there is no RFO and no HITM. It’s not a rare event. It’s literally impossible to happen. 

Which gives every finding exactly three ways to end:

| state | meaning | effect |
|---|---|---|
| `Unknown` | nobody checked | cannot raise severity, cannot retire the finding either |
| `Established` | an observation confirmed it | raises severity up to what the claim supports |
| `Refuted` | an observation showed it does not hold | if the claim was gating, the finding is withdrawn |

```
            finding, with its declared claims
                          |
                          v
             any gating claim refuted?
                    |           |
                   yes          no
                    |           |
                    v           v
              WITHDRAWN     any alternative established?
         the mechanism           |            |
         cannot occur           no           yes
                                 |            |
                                 v            v
                        INFORMATIONAL     severity = min of the caps,
                    nothing was asserted   max of what was established
```