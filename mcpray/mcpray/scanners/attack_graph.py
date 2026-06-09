"""Attack graph generator — maps MCP tool/resource data flows and highlights high-value attack paths."""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from enum import Enum

from ..findings import ServerInventory

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]+")


class NodeType(str, Enum):
    TOOL = "tool"
    RESOURCE = "resource"
    TEMPLATE = "template"
    PROMPT = "prompt"
    EXTERNAL = "external"      # external URLs/services mentioned in descriptions
    USER_INPUT = "user_input"  # parameters marked as user-controlled


class EdgeType(str, Enum):
    DATA_FLOW = "data_flow"               # tool output feeds into another tool's input
    DEPENDS_ON = "depends_on"             # tool description mentions another tool/resource
    USER_CONTROLLED = "user_controlled"   # user param reaches this node


@dataclass
class GraphNode:
    id: str
    name: str
    node_type: NodeType
    risk_score: float = 0.0   # 0.0-10.0
    risk_reason: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    from_id: str
    to_id: str
    edge_type: EdgeType
    label: str = ""


@dataclass
class AttackPath:
    nodes: list[str]          # sequence of node IDs
    description: str
    severity: str             # CRITICAL/HIGH/MEDIUM
    entry_point: str
    sink: str


@dataclass
class AttackGraphResult:
    target: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    mermaid_diagram: str = ""


class AttackGraphBuilder:
    """Builds an attack graph from MCP inventory without making any network calls."""

    # Dangerous sink keywords in tool descriptions
    _SINK_KEYWORDS = {
        "exec": 9.0, "shell": 9.0, "system": 8.5, "eval": 9.5,
        "subprocess": 8.0, "popen": 9.0, "os.system": 9.5,
        "query": 7.0, "sql": 7.0, "database": 6.0, "db.execute": 8.0,
        "fetch": 6.0, "http": 6.0, "request": 6.0, "url": 6.0, "curl": 7.0,
        "write": 7.0, "file": 6.5, "open": 6.0, "path": 5.0,
        "email": 6.0, "smtp": 7.0, "send": 6.0, "webhook": 7.0,
        "api_key": 8.0, "token": 7.0, "secret": 8.0, "password": 8.0,
        "ldap": 8.0, "active_directory": 8.0,
    }

    _HIGH_RISK_THRESHOLD = 7.0

    def __init__(self):
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    # ── Scoring & extraction ─────────────────────────────────────────────────────

    def _score_tool(self, tool: dict) -> tuple[float, str]:
        name = (tool.get("name") or "").lower()
        desc = (tool.get("description") or "").lower()
        haystack = f"{name} {desc}"

        best_score = 0.0
        hits: list[str] = []
        for kw, score in self._SINK_KEYWORDS.items():
            if kw in haystack:
                hits.append(kw)
                if score > best_score:
                    best_score = score

        if not hits:
            return 0.0, "no dangerous sink keywords detected"
        reason = "matched sink keywords: " + ", ".join(sorted(set(hits)))
        return best_score, reason

    def _extract_param_names(self, tool: dict) -> list[str]:
        schema = tool.get("inputSchema") or {}
        props = schema.get("properties") or {}
        if isinstance(props, dict):
            return list(props.keys())
        return []

    def _tool_output_keywords(self, tool: dict) -> set[str]:
        """Words from a tool's name + description that could describe its output."""
        text = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
        return {w for w in _WORD_RE.findall(text) if len(w) >= 4}

    # ── Edge discovery ───────────────────────────────────────────────────────────

    def _find_data_flows(self, tools: list[dict]) -> list[GraphEdge]:
        edges: list[GraphEdge] = []
        names = {(t.get("name") or "").lower(): t for t in tools}

        for a in tools:
            a_name = (a.get("name") or "").lower()
            a_id = f"tool:{a_name}"
            a_keywords = self._tool_output_keywords(a)

            for b in tools:
                b_name = (b.get("name") or "").lower()
                if b_name == a_name:
                    continue
                b_id = f"tool:{b_name}"

                # Explicit mention of tool A's name in tool B's description.
                b_desc = (b.get("description") or "").lower()
                if a_name and a_name in b_desc:
                    edges.append(GraphEdge(a_id, b_id, EdgeType.DEPENDS_ON, label="mentions"))
                    continue

                # Heuristic data flow: B's params/description overlap A's output words.
                b_params = {p.lower() for p in self._extract_param_names(b)}
                b_words = self._tool_output_keywords(b)
                overlap = a_keywords & (b_params | b_words)
                # Require a meaningful, specific overlap to limit noise.
                specific = {w for w in overlap if w not in _COMMON_WORDS}
                if len(specific) >= 2:
                    label = ",".join(sorted(specific)[:3])
                    edges.append(GraphEdge(a_id, b_id, EdgeType.DATA_FLOW, label=label))

        # Deduplicate (from,to,type).
        seen: set[tuple[str, str, str]] = set()
        unique: list[GraphEdge] = []
        for e in edges:
            key = (e.from_id, e.to_id, e.edge_type.value)
            if key not in seen:
                seen.add(key)
                unique.append(e)
        return unique

    def _find_external_deps(self, tools: list[dict]) -> list[GraphNode]:
        nodes: dict[str, GraphNode] = {}
        for t in tools:
            desc = t.get("description") or ""
            for match in _URL_RE.findall(desc):
                url = match.rstrip(".,;")
                node_id = f"external:{url}"
                if node_id not in nodes:
                    nodes[node_id] = GraphNode(
                        id=node_id,
                        name=url,
                        node_type=NodeType.EXTERNAL,
                        risk_score=6.0,
                        risk_reason="external service referenced in tool description",
                    )
                # Edge: tool depends on this external endpoint.
                t_id = f"tool:{(t.get('name') or '').lower()}"
                self._edges.append(
                    GraphEdge(t_id, node_id, EdgeType.DEPENDS_ON, label="external")
                )
        return list(nodes.values())

    # ── Path finding ─────────────────────────────────────────────────────────────

    def _adjacency(self) -> dict[str, list[str]]:
        adj: dict[str, list[str]] = {nid: [] for nid in self._nodes}
        for e in self._edges:
            if e.from_id in adj:
                adj[e.from_id].append(e.to_id)
        return adj

    def _find_attack_paths(self) -> list[AttackPath]:
        adj = self._adjacency()
        entry_points = [n.id for n in self._nodes.values() if n.node_type == NodeType.USER_INPUT]
        high_risk = {
            nid for nid, node in self._nodes.items()
            if node.node_type == NodeType.TOOL and node.risk_score >= self._HIGH_RISK_THRESHOLD
        }

        paths: list[AttackPath] = []
        seen_paths: set[tuple[str, ...]] = set()

        for entry in entry_points:
            # BFS over the graph tracking the path taken.
            queue: deque[list[str]] = deque([[entry]])
            while queue:
                path = queue.popleft()
                current = path[-1]
                if len(path) > 8:  # bound path length
                    continue
                for nxt in adj.get(current, []):
                    if nxt in path:  # avoid cycles
                        continue
                    new_path = path + [nxt]
                    if nxt in high_risk:
                        key = tuple(new_path)
                        if key not in seen_paths:
                            seen_paths.add(key)
                            paths.append(self._make_path(new_path, high_risk))
                    queue.append(new_path)

        return paths

    def _make_path(self, node_ids: list[str], high_risk: set[str]) -> AttackPath:
        sink_id = node_ids[-1]
        entry_id = node_ids[0]
        risky_in_path = [nid for nid in node_ids if nid in high_risk]
        names = [self._nodes[n].name for n in node_ids if n in self._nodes]

        if len(risky_in_path) >= 2:
            severity = "CRITICAL"
        else:
            sink = self._nodes.get(sink_id)
            score = sink.risk_score if sink else 0.0
            severity = "HIGH" if score >= 8.5 else "MEDIUM"

        desc = (
            "User-controlled input reaches a high-risk sink via: "
            + " -> ".join(names)
        )
        return AttackPath(
            nodes=list(node_ids),
            description=desc,
            severity=severity,
            entry_point=entry_id,
            sink=sink_id,
        )

    # ── Rendering ────────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_id(node_id: str) -> str:
        return re.sub(r"[^A-Za-z0-9_]", "_", node_id)

    def _render_mermaid(self) -> str:
        lines = ["flowchart LR"]
        class_for = {
            NodeType.TOOL: "tool",
            NodeType.RESOURCE: "resource",
            NodeType.TEMPLATE: "template",
            NodeType.PROMPT: "prompt",
            NodeType.EXTERNAL: "external",
            NodeType.USER_INPUT: "userinput",
        }

        for node in self._nodes.values():
            sid = self._safe_id(node.id)
            label = node.name.replace('"', "'")
            if node.node_type in (NodeType.TOOL, NodeType.EXTERNAL) and node.risk_score > 0:
                label = f"{label}<br/>risk {node.risk_score:.1f}"
            lines.append(f'    {sid}["{label}"]:::{class_for[node.node_type]}')

        for e in self._edges:
            if e.from_id not in self._nodes or e.to_id not in self._nodes:
                continue
            fsid = self._safe_id(e.from_id)
            tsid = self._safe_id(e.to_id)
            if e.label:
                lines.append(f'    {fsid} -->|{e.label}| {tsid}')
            else:
                lines.append(f"    {fsid} --> {tsid}")

        lines.append("    classDef tool fill:#0a84ff,stroke:#024,color:#fff;")
        lines.append("    classDef resource fill:#30d158,stroke:#063,color:#000;")
        lines.append("    classDef template fill:#5ac8fa,stroke:#036,color:#000;")
        lines.append("    classDef prompt fill:#bf5af2,stroke:#306,color:#fff;")
        lines.append("    classDef external fill:#ff453a,stroke:#600,color:#fff;")
        lines.append("    classDef userinput fill:#ffd60a,stroke:#660,color:#000;")
        return "\n".join(lines)

    # ── Entry point ──────────────────────────────────────────────────────────────

    def run(self, inventory: ServerInventory) -> AttackGraphResult:
        self._nodes = {}
        self._edges = []

        tools = inventory.tools or []
        resources = inventory.resources or []
        templates = inventory.resource_templates or []
        prompts = inventory.prompts or []

        # Tool nodes + user-input nodes per parameter.
        for tool in tools:
            name = tool.get("name") or "unnamed"
            tid = f"tool:{name.lower()}"
            score, reason = self._score_tool(tool)
            self._nodes[tid] = GraphNode(
                id=tid, name=name, node_type=NodeType.TOOL,
                risk_score=score, risk_reason=reason,
                metadata={"params": self._extract_param_names(tool)},
            )
            for param in self._extract_param_names(tool):
                uid = f"user_input:{name.lower()}:{param.lower()}"
                self._nodes[uid] = GraphNode(
                    id=uid, name=f"{name}.{param}", node_type=NodeType.USER_INPUT,
                    risk_score=0.0, risk_reason="user-controlled tool parameter",
                )
                self._edges.append(
                    GraphEdge(uid, tid, EdgeType.USER_CONTROLLED, label="input")
                )

        # Resource / template / prompt nodes.
        for r in resources:
            name = r.get("name") or r.get("uri") or "resource"
            rid = f"resource:{name.lower()}"
            self._nodes[rid] = GraphNode(id=rid, name=name, node_type=NodeType.RESOURCE)
        for t in templates:
            name = t.get("name") or t.get("uriTemplate") or "template"
            tid = f"template:{name.lower()}"
            self._nodes[tid] = GraphNode(id=tid, name=name, node_type=NodeType.TEMPLATE)
        for p in prompts:
            name = p.get("name") or "prompt"
            pid = f"prompt:{name.lower()}"
            self._nodes[pid] = GraphNode(id=pid, name=name, node_type=NodeType.PROMPT)

        # Edges: data flows + external dependencies.
        for e in self._find_data_flows(tools):
            self._edges.append(e)
        external_nodes = self._find_external_deps(tools)
        for node in external_nodes:
            self._nodes[node.id] = node

        attack_paths = self._find_attack_paths()
        mermaid = self._render_mermaid()

        return AttackGraphResult(
            target=inventory.target,
            nodes=list(self._nodes.values()),
            edges=list(self._edges),
            attack_paths=attack_paths,
            mermaid_diagram=mermaid,
        )


# Generic words excluded from data-flow overlap matching to reduce false positives.
_COMMON_WORDS = {
    "this", "that", "with", "from", "into", "your", "will", "have", "tool",
    "tools", "data", "value", "values", "input", "output", "name", "names",
    "result", "results", "return", "returns", "string", "object", "list",
    "param", "params", "parameter", "parameters", "given", "provided", "the",
    "and", "for", "use", "used", "uses", "using", "type", "field", "fields",
}
