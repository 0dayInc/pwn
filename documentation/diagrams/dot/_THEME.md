# PWN Diagram Visual Theme

All `.dot` files in this directory share one visual language so the rendered
SVGs feel like a single coherent product.

| Element              | Color     | Hex       |
|----------------------|-----------|-----------|
| Background           | slate-900 | `#0f172a` |
| Cluster border       | slate-700 | `#334155` |
| Cluster fill         | slate-800 | `#1e293b` |
| Actor / Entry (blue) | sky-300   | `#7dd3fc` |
| AI / Agent (purple)  | violet-300| `#c4b5fd` |
| Capability (green)   | emerald-300| `#6ee7b7`|
| Persistence (amber)  | amber-300 | `#fcd34d` |
| Target / Danger (red)| rose-300  | `#fda4af` |
| Edge default         | slate-400 | `#94a3b8` |
| Edge highlight       | sky-400   | `#38bdf8` |

Layout rules (to avoid criss-crossed edges):
1. `rankdir=TB` (or `LR` for pipelines), `newrank=true`, `splines=spline`.
2. Group every layer with `{rank=same; ...}` - edges go layer→layer only.
3. Side/back edges use `constraint=false` + `style=dashed` and are kept to ≤3 per diagram.
4. One `subgraph cluster_*` per logical layer with a translucent fill.
5. Node order inside a rank matches edge destinations in the next rank
   (Graphviz then draws parallel non-crossing edges).

Rebuild everything: `./build.sh` (from `documentation/diagrams/`).
