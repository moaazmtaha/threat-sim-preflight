from __future__ import annotations

import heapq
from typing import Iterable, Mapping

from .model import Action


def dependency_cycles(actions: Iterable[Action]) -> tuple[tuple[str, ...], ...]:
    dependencies = {action.id: action.depends_on for action in actions}
    visiting: list[str] = []
    active: set[str] = set()
    complete: set[str] = set()
    cycles: set[tuple[str, ...]] = set()

    def visit(action_id: str) -> None:
        if action_id in complete or action_id not in dependencies:
            return
        if action_id in active:
            start = visiting.index(action_id)
            cycle = visiting[start:] + [action_id]
            body = cycle[:-1]
            pivot = min(range(len(body)), key=lambda index: body[index])
            normalized = tuple(body[pivot:] + body[:pivot] + [body[pivot]])
            cycles.add(normalized)
            return
        active.add(action_id)
        visiting.append(action_id)
        for dependency in sorted(dependencies[action_id]):
            visit(dependency)
        visiting.pop()
        active.remove(action_id)
        complete.add(action_id)

    for action_id in sorted(dependencies):
        visit(action_id)
    return tuple(sorted(cycles))


def topological_order(actions: Iterable[Action]) -> tuple[str, ...]:
    action_list = tuple(actions)
    ids = {action.id for action in action_list}
    indegree = {action.id: 0 for action in action_list}
    dependents: dict[str, list[str]] = {action.id: [] for action in action_list}
    for action in action_list:
        for dependency in action.depends_on:
            if dependency in ids:
                indegree[action.id] += 1
                dependents[dependency].append(action.id)
    ready = [action_id for action_id, count in indegree.items() if count == 0]
    heapq.heapify(ready)
    ordered: list[str] = []
    while ready:
        current = heapq.heappop(ready)
        ordered.append(current)
        for dependent in sorted(dependents[current]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)
    return tuple(ordered) if len(ordered) == len(action_list) else ()
