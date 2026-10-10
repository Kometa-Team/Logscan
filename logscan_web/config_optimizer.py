"""Conservative, round-trip YAML anchor suggestions for extracted configs."""

from collections import defaultdict
from difflib import unified_diff
from io import StringIO

import yaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError
from ruamel.yaml.mergevalue import MergeValue


MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_YAML_EVENTS = 30000
MAX_DEPTH = 80
MAX_COMPARISONS = 20000


def _line_counts(original, optimized):
    before = len(original.splitlines())
    after = len(optimized.splitlines())
    saved = before - after
    return {"before": before, "after": after, "saved": saved,
            "reduction_percent": round(saved * 100 / before, 1) if before else 0}


def _signature(value, ancestors=frozenset(), ordered=False):
    if isinstance(value, (dict, list)):
        if id(value) in ancestors:
            raise ValueError("Recursive YAML aliases cannot be optimized.")
        ancestors = ancestors | {id(value)}
        if isinstance(value, dict):
            pairs = [(_signature(key, ancestors, ordered), _signature(item, ancestors, ordered))
                     for key, item in value.items()]
            return ("mapping", tuple(pairs if ordered else sorted(pairs, key=repr)))
        return ("sequence", tuple(_signature(item, ancestors, ordered) for item in value))
    return (type(value).__name__, repr(value))


def _has_comments(value, visited=None):
    visited = set() if visited is None else visited
    if not isinstance(value, (CommentedMap, CommentedSeq)) or id(value) in visited:
        return False
    visited.add(id(value))
    if value.ca.comment or value.ca.items or value.ca.end:
        return True
    children = value.values() if isinstance(value, dict) else value
    return any(_has_comments(child, visited) for child in children)


def optimize_config(config: str) -> dict:
    if not config.strip():
        raise ValueError("No config block was found in this log.")
    if len(config.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ValueError("This config is too large for anchor optimization (maximum 2 MiB).")
    try:
        depth = 0
        anchor_names = set()
        for count, event in enumerate(yaml.parse(config)):
            if count >= MAX_YAML_EVENTS:
                raise ValueError("This config is too complex for anchor optimization.")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > MAX_DEPTH:
                    raise ValueError("This config is nested too deeply for anchor optimization.")
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if getattr(event, "anchor", None):
                anchor_names.add(event.anchor)
        pending = [(yaml.compose(config), frozenset())]
        expanded_count = 0
        while pending:
            item, ancestors = pending.pop()
            expanded_count += 1
            if expanded_count > MAX_YAML_EVENTS:
                raise ValueError("Expanded YAML aliases are too complex for anchor optimization.")
            if isinstance(item, (yaml.MappingNode, yaml.SequenceNode)):
                if id(item) in ancestors:
                    raise ValueError("Recursive YAML aliases cannot be optimized.")
                children = [child for pair in item.value for child in pair] if isinstance(item, yaml.MappingNode) else item.value
                pending.extend((child, ancestors | {id(item)}) for child in children)
        original = yaml.safe_load(config)
        original_signature = _signature(original)
        round_trip = YAML()
        round_trip.version = (1, 1)
        round_trip.preserve_quotes = True
        round_trip.width = 4096
        round_trip.indent(mapping=2, sequence=4, offset=2)
        document = round_trip.load(config)
    except (yaml.YAMLError, YAMLError, RecursionError) as exc:
        raise ValueError("Anchor optimization requires valid, non-recursive YAML.") from exc
    if not isinstance(document, CommentedMap):
        raise ValueError("Anchor optimization requires a YAML config mapping.")

    exact = {}
    mappings = defaultdict(list)
    changes = {}
    visited = set()
    comparisons = 0

    def anchor(source, source_path, target_path, kind):
        if not source.anchor.value:
            index = 1
            while f"logscan_shared_{index}" in anchor_names:
                index += 1
            source.yaml_set_anchor(f"logscan_shared_{index}", always_dump=True)
            anchor_names.add(source.anchor.value)
        name = source.anchor.value
        change = changes.setdefault(name, {
            "anchor": name, "source": source_path, "locations": [source_path], "kind": kind,
        })
        change["locations"].append(target_path)

    def visit(value, parent=None, key=None, path="config", role="root"):
        nonlocal comparisons
        if not isinstance(value, (CommentedMap, CommentedSeq)) or id(value) in visited:
            return
        visited.add(id(value))
        signature = _signature(value, ordered=True)
        # Only replace unanchored, comment-free blocks; existing references stay intact.
        replaceable = parent is not None and not value.anchor.value and not _has_comments(value)
        key_order = tuple(value) if isinstance(value, CommentedMap) else ()
        signature_key = (role, signature, key_order)
        if replaceable and signature_key in exact:
            source, source_path = exact[signature_key]
            anchor(source, source_path, path, "shared block")
            parent[key] = source
            return
        if isinstance(value, CommentedMap) and not getattr(value, "_yaml_merge", None) and replaceable:
            for source, source_path in mappings[role]:
                comparisons += 1
                if comparisons > MAX_COMPARISONS:
                    break
                if path.startswith(source_path + ".") or path.startswith(source_path + "["):
                    continue
                if not source.keys() <= value.keys():
                    continue
                if any(isinstance(item, (dict, list)) for item in source.values()):
                    continue
                shared = [item for item in source if _signature(source[item]) == _signature(value[item])]
                if len(shared) < 2:
                    continue
                anchor(source, source_path, path, "shared settings with overrides")
                for item in shared:
                    del value[item]
                merge = MergeValue()
                merge.append(source)
                merge.merge_pos = 0
                value.add_yaml_merge(merge)
                break
        # Avoid trivial aliases and do not merge blocks containing existing merge rules.
        if len(value) >= 2:
            exact.setdefault(signature_key, (value, path))
            if isinstance(value, CommentedMap) and not getattr(value, "_yaml_merge", None) and len(mappings[role]) < 100:
                mappings[role].append((value, path))
        children = list(value.non_merged_items()) if isinstance(value, CommentedMap) else list(enumerate(value))
        for child_key, child in children:
            child_path = f"{path}[{child_key}]" if isinstance(value, list) else f"{path}.{child_key}"
            visit(child, value, child_key, child_path, "[]" if isinstance(value, list) else str(child_key))

    visit(document)
    if not changes:
        return {"status": "unchanged", "changes": [], "diff": "", "optimized_config": None,
                "line_counts": _line_counts(config, config),
                "message": "No useful repetition found."}
    stream = StringIO()
    round_trip.dump(document, stream)
    optimized = stream.getvalue()
    try:
        if _signature(yaml.safe_load(optimized)) != original_signature:
            raise ValueError("The proposed anchors changed resolved values; no download was generated.")
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("The proposed YAML could not be verified; no download was generated.") from exc
    return {
        "status": "optimized", "changes": list(changes.values()),
        "line_counts": _line_counts(config, optimized),
        "optimized_config": optimized,
        "diff": "".join(unified_diff([line + "\n" for line in config.splitlines()], optimized.splitlines(keepends=True),
                                     fromfile="original.yml", tofile="anchored.yml")),
        "message": "Resolved config values verified unchanged.",
    }
