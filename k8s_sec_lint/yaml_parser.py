"""Lightweight 100% stdlib multi-document YAML parser for Kubernetes manifests."""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple


def _strip_comment(line: str) -> str:
    """Strip inline YAML comments outside of single/double quotes."""
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            if i == 0 or line[i - 1] != "\\":
                in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1].isspace():
                return line[:i].rstrip()
        i += 1
    return line.rstrip()


def _parse_scalar(val: str) -> Any:
    """Convert a YAML scalar string into Python types."""
    val = val.strip()
    if not val or val in ("null", "Null", "NULL", "~"):
        return None
    if val in ("true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"):
        return True
    if val in ("false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"):
        return False

    if (val.startswith('"') and val.endswith('"') and len(val) >= 2) or (
        val.startswith("'") and val.endswith("'") and len(val) >= 2
    ):
        inner = val[1:-1]
        if val.startswith('"'):
            inner = inner.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
        return inner

    # Inline list: [a, b, c]
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item) for item in _split_inline(inner)]

    # Inline dict: {a: 1, b: 2}
    if val.startswith("{") and val.endswith("}"):
        inner = val[1:-1].strip()
        if not inner:
            return {}
        result = {}
        for part in _split_inline(inner):
            if ":" in part:
                k, v = part.split(":", 1)
                result[_parse_scalar(k)] = _parse_scalar(v)
        return result

    # Integer
    if re.fullmatch(r"-?\d+", val):
        try:
            return int(val)
        except ValueError:
            pass

    # Float
    if re.fullmatch(r"-?\d+\.\d+", val):
        try:
            return float(val)
        except ValueError:
            pass

    return val


def _split_inline(text: str) -> List[str]:
    """Split comma-separated inline YAML items respecting quotes and brackets."""
    items: List[str] = []
    buf: List[str] = []
    depth = 0
    in_single = False
    in_double = False
    for ch in text:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch in ("[", "{"):
                depth += 1
            elif ch in ("]", "}"):
                depth = max(0, depth - 1)
            elif ch == "," and depth == 0:
                items.append("".join(buf).strip())
                buf = []
                continue
        buf.append(ch)
    if buf:
        items.append("".join(buf).strip())
    return items


def _split_key_value(text: str) -> Optional[Tuple[str, str]]:
    """Split 'key: value' respecting quotes."""
    in_single = False
    in_double = False
    for i, ch in enumerate(text):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            if i + 1 == len(text) or text[i + 1].isspace():
                key = text[:i].strip()
                if (key.startswith('"') and key.endswith('"')) or (
                    key.startswith("'") and key.endswith("'")
                ):
                    key = key[1:-1]
                val = text[i + 1 :].strip()
                return key, val
    return None


def _tokenize(text: str) -> List[Tuple[int, str]]:
    """Return list of (indent, stripped_content) for non-empty, non-comment lines."""
    tokens: List[Tuple[int, str]] = []
    for raw_line in text.splitlines():
        cleaned = _strip_comment(raw_line)
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        tokens.append((indent, cleaned.strip()))
    return tokens


def _parse_block(tokens: List[Tuple[int, str]], idx: int, base_indent: int) -> Tuple[Any, int]:
    """Recursively parse a YAML block (dict or list) starting at idx."""
    if idx >= len(tokens):
        return None, idx

    _, first_line = tokens[idx]
    if first_line.startswith("- ") or first_line == "-":
        return _parse_list(tokens, idx, base_indent)
    return _parse_dict(tokens, idx, base_indent)


def _parse_dict(tokens: List[Tuple[int, str]], idx: int, base_indent: int) -> Tuple[dict, int]:
    result: dict = {}
    n = len(tokens)
    while idx < n:
        indent, line = tokens[idx]
        if indent < base_indent:
            break
        if indent > base_indent:
            # Unexpected indent; skip or break
            break
        if line.startswith("- ") or line == "-":
            break

        kv = _split_key_value(line)
        if kv is None:
            idx += 1
            continue

        key, val_str = kv
        idx += 1
        if val_str == "" or val_str in ("|", ">", "|-", ">-"):
            if val_str in ("|", ">", "|-", ">-"):
                # Multiline scalar block
                lines_buf: List[str] = []
                block_indent = None
                while idx < n and tokens[idx][0] > base_indent:
                    if block_indent is None:
                        block_indent = tokens[idx][0]
                    lines_buf.append(tokens[idx][1])
                    idx += 1
                result[key] = "\n".join(lines_buf)
            elif idx < n and tokens[idx][0] > base_indent:
                child_val, idx = _parse_block(tokens, idx, tokens[idx][0])
                result[key] = child_val
            elif idx < n and tokens[idx][0] == base_indent and (
                tokens[idx][1].startswith("- ") or tokens[idx][1] == "-"
            ):
                # YAML allows list items at same indent as parent key
                child_val, idx = _parse_list(tokens, idx, base_indent)
                result[key] = child_val
            else:
                result[key] = None
        else:
            result[key] = _parse_scalar(val_str)

    return result, idx


def _parse_list(tokens: List[Tuple[int, str]], idx: int, base_indent: int) -> Tuple[list, int]:
    result: list = []
    n = len(tokens)
    while idx < n:
        indent, line = tokens[idx]
        if indent < base_indent:
            break
        if indent > base_indent:
            break
        if not (line.startswith("- ") or line == "-"):
            break

        after_dash = line[2:].strip() if line.startswith("- ") else ""
        idx += 1

        if not after_dash:
            if idx < n and tokens[idx][0] > base_indent:
                child, idx = _parse_block(tokens, idx, tokens[idx][0])
                result.append(child)
            else:
                result.append(None)
            continue

        kv = _split_key_value(after_dash)
        if kv is not None:
            # List item is a dict starting on the '- key: val' line
            item_dict: dict = {}
            k, v = kv
            item_indent = indent + 2
            if v == "":
                if idx < n and tokens[idx][0] > item_indent:
                    child, idx = _parse_block(tokens, idx, tokens[idx][0])
                    item_dict[k] = child
                elif idx < n and tokens[idx][0] == item_indent and (
                    tokens[idx][1].startswith("- ") or tokens[idx][1] == "-"
                ):
                    child, idx = _parse_list(tokens, idx, item_indent)
                    item_dict[k] = child
                else:
                    item_dict[k] = None
            else:
                item_dict[k] = _parse_scalar(v)

            # Parse remaining keys at item_indent (or > indent)
            if idx < n and tokens[idx][0] > indent:
                sub_indent = tokens[idx][0]
                if not (tokens[idx][1].startswith("- ") or tokens[idx][1] == "-"):
                    more_dict, idx = _parse_dict(tokens, idx, sub_indent)
                    item_dict.update(more_dict)
            result.append(item_dict)
        else:
            result.append(_parse_scalar(after_dash))

    return result, idx


def parse_yaml_documents(text: str) -> List[Any]:
    """Parse a multi-document YAML string into a list of Python objects."""
    docs: List[Any] = []
    current_lines: List[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "---" or stripped.startswith("--- "):
            if current_lines:
                tokens = _tokenize("\n".join(current_lines))
                if tokens:
                    obj, _ = _parse_block(tokens, 0, tokens[0][0])
                    if obj is not None:
                        docs.append(obj)
                current_lines = []
            continue
        if stripped == "...":
            continue
        current_lines.append(line)

    if current_lines:
        tokens = _tokenize("\n".join(current_lines))
        if tokens:
            obj, _ = _parse_block(tokens, 0, tokens[0][0])
            if obj is not None:
                docs.append(obj)

    return docs
