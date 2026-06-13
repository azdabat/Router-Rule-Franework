## Router Rules vs Primitives — The Three-Layer Detection Architecture

> *"A primitive captures what happened.*  
> *A router rule asks whether it matters.*  
> *A composite confirms that it does."*

---

### Primitives Are Atomic

A primitive is the irreducible telemetric fact. It answers one question with zero inference:

```
scrcons.exe loaded vbscript.dll
bitsadmin.exe executed
rundll32.exe invoked comsvcs.dll
```

No scoring. No context. No intent. Just the raw substrate event captured and indexed. Primitives live in the **atomic sentinel layer** — the silent 30-day rolling index that catches what composites miss and connects Day 0 staging to Day 3 activation.

---

### Router Rules Are Behavioural Threat Hunts

A router rule is a behavioural hunt that has been given structure, a scoring model, and a routing output. It asks a higher-order question than a primitive:

```
Is there evidence of ingress transfer intent anywhere on this estate?
Is there evidence of AD reconnaissance activity anywhere on this estate?
Is there evidence of script proxy execution intent anywhere on this estate?
```

These are hunt hypotheses expressed as always-on rules. The four-phase MTDF structure, the convergence scoring, the soft penalties, the routing directive — all of that is behavioural analysis, not raw telemetry capture. A router rule is operationally a threat hunt that has been promoted to a scheduled detection.

---

### The Three-Layer Model

```mermaid
graph TD
    P["PRIMITIVE LAYER\nAtomic substrate facts\nNo scoring · No inference\nSilent 30-day index\n'scrcons.exe loaded vbscript.dll'\n'bitsadmin.exe executed'"]

    R["ROUTER RULE LAYER\nBehavioural threat hunt\nIntent detection across surfaces\nScored · Routed · Temporary\n'Is ingress transfer in progress?'\n'Is AD recon in progress?'"]

    C["COMPOSITE SENSOR LAYER\nMinimum truth confirmation\nSingle technique · Single noise domain\nHigh-confidence production alert\n'bitsadmin /transfer to AppData confirmed'\n'comsvcs MiniDump on LSASS confirmed'"]

    I["INCIDENT LAYER\nNarrative stitching\nEntity key correlation\nAttack story assembled"]

    P -->|"Entity key\n30-day index"| C
    R -->|"RoutingDirective:\nRun composite on DeviceId=X"| C
    C -->|"HunterDirective:\nMinimum truth confirmed"| I
    P -->|"Direct stitch\nwhen composite\nnot yet built"| I
```

---

### The Practical Distinction

| Layer | Question Asked | Output | Lifecycle |
|-------|---------------|--------|-----------|
| **Primitive** | Did this substrate event exist? | Raw indexed fact | Permanent |
| **Router Rule** | Is this adversary goal in progress? | RoutingDirective | Temporary |
| **Composite Sensor** | Did this specific attack happen? | HunterDirective | Permanent |
| **Incident Layer** | What is the full attack story? | Narrative + blast radius | Case lifecycle |

---

### What Happens When You Strip a Router Rule Down

Strip the scoring, remove the routing, remove the phase structure, keep only the Phase 1 filter — you get a primitive collector. That is literally what the atomic sentinel layer is built from.

The Phase 1 broad surface filter of Hunt Pack 04 (Ingress Tool Transfer), run with no threshold and no scoring, becomes a primitive index of every LOLBin downloader execution on the estate for the last 30 days.

```mermaid
flowchart LR
    subgraph RR["Router Rule\nHunt Pack 04"]
        P1["Phase 1\nBroad filter\nbitsadmin · certutil\ncurl · powershell"]
        P2["Phase 2\nSignal enrichment\nIsMasqueraded · HasScript\nBadParent · StagingPath"]
        P3["Phase 3\nRouting score\nBase 0 · Threshold 30"]
        P4["Phase 4\nRoutingDirective\nPIVOT TO composite"]
        P1 --> P2 --> P3 --> P4
    end

    subgraph Primitive["Primitive Collector\nStripped to Phase 1 only"]
        PP1["Phase 1 filter only\nbitsadmin · certutil\ncurl · powershell\nNo scoring · No threshold\n30-day rolling index"]
    end

    subgraph Composite["Composite Sensor\nT1197 BITSAdmin"]
        C1["Minimum truth\nbitsadmin /transfer\n+ remote URL"]
        C2["Reinforcement\nstaging path · parent\nextension · domain"]
        C3["Score + threshold\nBase 55 · >= 75"]
        C4["HunterDirective\nconfirms truth"]
        C1 --> C2 --> C3 --> C4
    end

    PP1 -.->|"30-day index\nentity key"| Composite
    RR -->|"RoutingDirective"| Composite

    style Primitive fill:#0a1a0f,stroke:#00ff88,color:#00ff88
    style RR fill:#1a1000,stroke:#f59e0b,color:#fcd34d
    style Composite fill:#0a1628,stroke:#00aaff,color:#7dd3fc
```

That is architecturally valid and useful — but it serves a different purpose. The primitive index is the net. The router rule is the structured hunt. The composite is the anchor.

---

### The Insight That Connects All Three

The MTDF framework already implicitly contained all three layers:

```mermaid
graph LR
    subgraph Before["MTDF Before Router Rule Doctrine"]
        A1["Atomic Sentinel\nPrimitive collector\nSilent 30-day index"]
        A2["Composite Sensor\nMinimum truth anchor\nHunterDirective"]
        A3["Incident Layer\nNarrative stitching"]
        A1 -->|"Entity key"| A2 --> A3
        A1 -->|"Direct stitch"| A3
    end

    subgraph After["MTDF With Router Rule Doctrine"]
        B1["Atomic Sentinel\nPrimitive collector\nSilent 30-day index"]
        B2["Router Rule\nBehavioural hunt\nIntent detection\nRoutingDirective"]
        B3["Composite Sensor\nMinimum truth anchor\nHunterDirective"]
        B4["Incident Layer\nNarrative stitching"]
        B1 -->|"Entity key"| B3
        B2 -->|"PIVOT TO composite\non DeviceId=X"| B3
        B3 --> B4
        B1 -->|"Direct stitch"| B4
    end
```

The router rule fills the **gap between primitive and composite** — it is the structured behavioural hunt that surfaces intent across technique families while the composites are being built to confirm truth.

---

### The Coverage Pipeline in Full

```mermaid
flowchart TD
    A["New technique identified\nor incident reveals gap"] --> B

    B{Composite\nalready exists?}
    B -->|Yes| C["Deploy composite\nAlert on minimum truth\nPermanent sensor"]
    B -->|No| D

    D{Single technique\nor multiple?}
    D -->|Single| E["Build primitive first\n30-day index\nno threshold"]
    D -->|Multiple| F

    E --> G["Build composite\nADX validate\nDeploy as permanent sensor"]

    F{Same noise domain\nacross all?}
    F -->|Yes| H["Build composite pack\none composite per technique\nshared suppression model"]
    F -->|No — different noise| I["Deploy router rule NOW\nstructured behavioural hunt\nBase 0 · Threshold 30"]

    I --> J["Build primitives\nfor each technique\n30-day index"]
    J --> K["Build composites\none per technique\nADX validate each"]
    K --> L["Retire technique\nfrom router rule\nUpdate decomposition tracker"]
    L --> M{All techniques\nretired?}
    M -->|Yes| N["Retire router rule\nFull composite coverage\nNo gap remains"]
    M -->|No| K

    style I fill:#1a1000,stroke:#f59e0b,color:#fcd34d
    style C fill:#0a1628,stroke:#00aaff,color:#7dd3fc
    style G fill:#0a1628,stroke:#00aaff,color:#7dd3fc
    style H fill:#0a1628,stroke:#00aaff,color:#7dd3fc
    style N fill:#0a1a0f,stroke:#00ff88,color:#00ff88
```

---

### Summary

```
Primitive    → the substrate event, indexed, no inference
Router Rule  → the behavioural hunt, structured, intent-level, temporary
Composite    → the minimum truth confirmation, permanent, high-confidence
Incident     → the narrative, assembled from all three

Strip a router rule to Phase 1 only → primitive collector
Promote a router rule technique to ADX-validated anchor → composite sensor
A router rule that is never retired → coverage debt
A composite without a primitive backing it → gap in the 30-day index
```

> **The primitive is the net.**  
> **The router rule is the structured hunt.**  
> **The composite is the anchor.**  
> **The incident is the story.**
