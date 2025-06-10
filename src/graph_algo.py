from CFG_recover import Funcnode
from typing import List, Dict, Set


class CallGraph:
    def __init__(self, _init_funcs: List[Funcnode]):
        self.addr_to_idx: Dict[int, int] = {}  # func.addr -> node idx
        self.idx_to_func: List[Funcnode] = []  # node idx -> func
        self.num_vertices: int = 0  # number of vertices
        self.adj: List[List[int]] = []  # adjacency list
        self.scc_ids: List[int] = []  # SCC id for each node (Tarjan Algo)
        self.scc_count = 0
        self.scc_dag: List[List[int]] = []
        self.scc_funcidx_map: List[List[int]] = []
        self._build(_init_funcs)
        self._find_sccs()
        self._build_contracted_dag()
        self._build_scc_funcidx_map()

    # Build the initial call graph from the list of interesting functions
    def _build(self, init_funcs: List[Funcnode]):
        def _add_func(f: Funcnode):
            addr = f.addr
            self.adj.append([])
            self.addr_to_idx[addr] = self.num_vertices
            self.idx_to_func.append(f)
            self.num_vertices += 1
            visited_funcs.add(addr)

        visited_funcs: Set[int] = set()
        for f in init_funcs:
            _add_func(f)

        funcs = init_funcs.copy()  # list of interesting functions
        while funcs:
            f = funcs.pop(0)
            for xref in f.xrefs:
                caller = xref.parent_funcnode
                if caller.addr not in visited_funcs:
                    _add_func(caller)
                    funcs.append(caller)
                # Add edge (caller -> callee)
                callee_idx = self.addr_to_idx[f.addr]
                caller_idx = self.addr_to_idx[caller.addr]
                if callee_idx not in self.adj[caller_idx]:
                    self.adj[caller_idx].append(callee_idx)

    # Tarjan's algo
    def _find_sccs(self):
        index = 0
        stack = []
        on_stack = [False] * self.num_vertices
        indices = [-1] * self.num_vertices
        lowlinks = [-1] * self.num_vertices
        self.scc_ids = [-1] * self.num_vertices
        self.scc_count = 0

        def _strong_connect(v: int):
            nonlocal index
            indices[v] = index
            lowlinks[v] = index
            index += 1
            stack.append(v)
            on_stack[v] = True

            for w in self.adj[v]:
                if indices[w] == -1:  # Unvisited: keep DFS
                    _strong_connect(w)
                    lowlinks[v] = min(lowlinks[v], lowlinks[w])
                elif on_stack[w]:  # Visited and on stack: back edge
                    lowlinks[v] = min(lowlinks[v], indices[w])

            if lowlinks[v] == indices[v]:  # Root of SCC
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    self.scc_ids[w] = self.scc_count
                    if w == v:
                        break
                self.scc_count += 1

        for v in range(self.num_vertices):
            if indices[v] == -1:
                _strong_connect(v)

    # Build SCCs DAG
    def _build_contracted_dag(self):
        self.scc_dag = [[] for _ in range(self.scc_count)]
        for v in range(self.num_vertices):
            for w in self.adj[v]:
                scc_v, scc_w = self.scc_ids[v], self.scc_ids[w]
                if scc_v != scc_w and scc_w not in self.scc_dag[scc_v]:
                    self.scc_dag[scc_v].append(scc_w)

    # Reversed topological sort of SCCs DAG
    def reverse_topological_sort(self) -> List[int]:
        visited = [False] * self.scc_count
        stack = []

        def dfs(v):
            visited[v] = True
            for neighbor in self.scc_dag[v]:
                if not visited[neighbor]:
                    dfs(neighbor)
            stack.append(v)

        for i in range(self.scc_count):
            if not visited[i]:
                dfs(i)

        # We don't reverse at the end because this is exactly the order the nodes should be visited
        return stack

    # scc_idx -> list of function indices
    def _build_scc_funcidx_map(self):
        self.scc_funcidx_map = [[] for _ in range(self.scc_count)]
        for i, scc in enumerate(self.scc_ids):
            self.scc_funcidx_map[scc].append(i)

    def dump(self):
        print("----- Call Graph -----")
        print(f"  Number of vertices: {self.num_vertices}")
        print(f"  Number of SCCs: {self.scc_count}\n")
        # If there is an edge from i to i itself, it's recursion
        for i in range(self.num_vertices):
            if i in self.adj[i]:
                print(f"  Func {self.idx_to_func[i].addr:x} is recursive")
        for i in range(self.num_vertices):
            print(f"  Func {self.idx_to_func[i].addr:x} (SCC ID: {self.scc_ids[i]}):")
            for j in self.adj[i]:
                print(f"    -> {self.idx_to_func[j].addr:x}")

        # Print scc_dag
        print("\n  SCC graph:")
        for scc, neighbors in enumerate(self.scc_dag):
            print(f"  SCC {scc}:")
            for neighbor in neighbors:
                print(f"    -> SCC {neighbor}")

        # Print scc-to-indice map
        print("\n  SCC-to-funcs")
        scc_map = self.scc_funcidx_map
        for scc, nodes in enumerate(scc_map):
            print(f"  SCC {scc}:")
            for node in nodes:
                print(f"    Func {self.idx_to_func[node].addr:x}")

        print("\n  Topologically sorted SCCs:")
        sorted_sccs = self.reverse_topological_sort()
        for scc in sorted_sccs:
            print(f"  SCC {scc}:")
            for i, node_scc in enumerate(self.scc_ids):
                if node_scc == scc:
                    print(f"    Func {self.idx_to_func[i].addr:x}")
        print("----------------------")

    def build_func_to_scc_id(self) -> Dict[int, int]:
        func_to_scc_id = {}
        for i, func in enumerate(self.idx_to_func):
            func_to_scc_id[func.addr] = self.scc_ids[i]
        return func_to_scc_id
