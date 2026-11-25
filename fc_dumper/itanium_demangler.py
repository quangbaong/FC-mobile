"""Lightweight pure-Python Itanium C++ ABI name demangler for RTTI & ELF symbols."""

from __future__ import annotations

_BUILTIN_TYPES = {
    "v": "void",
    "w": "wchar_t",
    "b": "bool",
    "c": "char",
    "a": "signed char",
    "h": "unsigned char",
    "s": "short",
    "t": "unsigned short",
    "i": "int",
    "j": "unsigned int",
    "l": "long",
    "m": "unsigned long",
    "x": "long long",
    "y": "unsigned long long",
    "n": "__int128",
    "o": "unsigned __int128",
    "f": "float",
    "d": "double",
    "e": "long double",
    "z": "...",
    "Da": "auto",
    "Dn": "std::nullptr_t",
    "Ds": "char16_t",
    "Di": "char32_t",
    "Du": "char8_t",
}

_STD_SUBS = {
    "St": "std",
    "Sa": "std::allocator",
    "Sb": "std::basic_string",
    "Ss": "std::string",
    "Si": "std::istream",
    "So": "std::ostream",
    "Sd": "std::iostream",
}


class _Demangler:
    def __init__(self, src: str) -> None:
        self.s = src
        self.pos = 0
        self.subs: list[str] = []

    def _eof(self) -> bool:
        return self.pos >= len(self.s)

    def _peek(self, n: int = 1) -> str:
        return self.s[self.pos : self.pos + n]

    def _read_number(self) -> int | None:
        start = self.pos
        while self.pos < len(self.s) and self.s[self.pos].isdigit():
            self.pos += 1
        if self.pos == start:
            return None
        return int(self.s[start : self.pos])

    def _read_source_name(self) -> str:
        n = self._read_number()
        if n is None or n <= 0 or self.pos + n > len(self.s):
            raise ValueError("Invalid source-name length")
        name = self.s[self.pos : self.pos + n]
        self.pos += n
        return name

    def _add_sub(self, text: str) -> str:
        if text and (not self.subs or self.subs[-1] != text):
            self.subs.append(text)
        return text

    def _read_sub(self) -> str:
        self.pos += 1  # consume 'S'
        if self._peek() in ("t", "a", "b", "s", "i", "o", "d"):
            code = "S" + self.s[self.pos]
            self.pos += 1
            return _STD_SUBS[code]
        if self._peek() == "_":
            self.pos += 1
            return self.subs[0] if self.subs else "S_"
        idx_chars: list[str] = []
        while not self._eof() and self._peek() != "_":
            idx_chars.append(self.s[self.pos])
            self.pos += 1
        if self._peek() != "_":
            raise ValueError("Unterminated substitution")
        self.pos += 1
        idx = int("".join(idx_chars), 36) + 1
        return self.subs[idx] if 0 <= idx < len(self.subs) else f"S{idx - 1}_"

    def _read_template_args(self) -> str:
        self.pos += 1  # consume 'I'
        args: list[str] = []
        while not self._eof() and self._peek() != "E":
            args.append(self._parse_template_arg())
        if self._peek() == "E":
            self.pos += 1
        return "<" + ", ".join(args) + ">"

    def _parse_template_arg(self) -> str:
        if self._peek() == "L":
            self.pos += 1
            t = self._parse_type()
            neg = False
            if self._peek() == "n":
                neg = True
                self.pos += 1
            val_start = self.pos
            while not self._eof() and self._peek() != "E":
                self.pos += 1
            val = ("-" if neg else "") + self.s[val_start : self.pos]
            if self._peek() == "E":
                self.pos += 1
            if t == "bool":
                return "true" if val == "1" else ("false" if val == "0" else val)
            return val
        if self._peek() == "X":
            self.pos += 1
            depth = 1
            start = self.pos
            while not self._eof() and depth > 0:
                if self._peek() == "E":
                    depth -= 1
                    if depth == 0:
                        expr = self.s[start : self.pos]
                        self.pos += 1
                        return expr
                self.pos += 1
            return self.s[start:]
        return self._parse_type()

    def _parse_nested_name(self) -> str:
        self.pos += 1  # consume 'N'
        while self._peek() in ("r", "V", "K", "O", "R"):
            self.pos += 1
        parts: list[str] = []
        if self._peek(2) == "St":
            self.pos += 2
            parts.append("std")
        while not self._eof() and self._peek() != "E":
            ch = self._peek()
            if ch == "S":
                base = self._read_sub()
                parts.append(base)
                self._add_sub("::".join(parts))
            elif ch == "I":
                targs = self._read_template_args()
                if parts:
                    parts[-1] += targs
                else:
                    parts.append(targs)
                self._add_sub("::".join(parts))
            elif ch == "C" and self._peek(2) in ("C1", "C2", "C3"):
                self.pos += 2
                if parts:
                    parts.append(parts[-1].split("<", 1)[0])
            elif ch == "D" and self._peek(2) in ("D0", "D1", "D2"):
                self.pos += 2
                if parts:
                    parts.append("~" + parts[-1].split("<", 1)[0])
            elif ch == "Z":
                self.pos += 1
                inner = self._parse_encoding()
                if self._peek() == "E":
                    self.pos += 1
                parts.append(f"[{inner}]")
                self._add_sub("::".join(parts))
            elif ch.isdigit():
                name = self._read_source_name()
                parts.append(name)
                if name != "__ndk1":
                    self._add_sub("::".join(parts))
            else:
                # Unknown tag inside nested name; return best effort
                break
        if self._peek() == "E":
            self.pos += 1
        return "::".join(parts)

    def _parse_type(self) -> str:
        if self._eof():
            return "?"
        ch = self._peek()
        if ch in ("K", "V", "r"):
            qual = {"K": "const ", "V": "volatile ", "r": "restrict "}[ch]
            self.pos += 1
            res = qual + self._parse_type()
            return self._add_sub(res)
        if ch == "P":
            self.pos += 1
            return self._add_sub(self._parse_type() + "*")
        if ch == "R":
            self.pos += 1
            return self._add_sub(self._parse_type() + "&")
        if ch == "O":
            self.pos += 1
            return self._add_sub(self._parse_type() + "&&")
        if ch == "F":
            self.pos += 1
            ret = self._parse_type()
            params: list[str] = []
            while not self._eof() and self._peek() != "E":
                params.append(self._parse_type())
            if self._peek() == "E":
                self.pos += 1
            if params == ["void"]:
                params = []
            return self._add_sub(f"{ret}({', '.join(params)})")
        if ch == "A":
            self.pos += 1
            dim_start = self.pos
            while not self._eof() and self._peek() != "_":
                self.pos += 1
            dim = self.s[dim_start : self.pos]
            if self._peek() == "_":
                self.pos += 1
            elem = self._parse_type()
            return self._add_sub(f"{elem}[{dim}]")
        if ch == "N":
            return self._parse_nested_name()
        if ch == "S":
            res = self._read_sub()
            if self._peek() == "I":
                res = res + self._read_template_args()
                self._add_sub(res)
            return res
        if ch == "Z":
            self.pos += 1
            inner = self._parse_encoding()
            if self._peek() == "E":
                self.pos += 1
            return inner
        if ch.isdigit():
            res = self._read_source_name()
            self._add_sub(res)
            if self._peek() == "I":
                res = res + self._read_template_args()
                self._add_sub(res)
            return res
        two = self._peek(2)
        if two in _BUILTIN_TYPES:
            self.pos += 2
            return _BUILTIN_TYPES[two]
        if ch in _BUILTIN_TYPES:
            self.pos += 1
            return _BUILTIN_TYPES[ch]
        if ch == "U":
            self.pos += 1
            q = self._read_source_name()
            return f"{self._parse_type()} {q}"
        raise ValueError(f"Unsupported type token at {self.pos}: {self.s[self.pos:]}")

    def _parse_encoding(self) -> str:
        if self._peek(2) == "St":
            self.pos += 2
            name = "std::" + self._read_source_name()
            return name
        if self._peek() == "N":
            return self._parse_nested_name()
        if self._peek() == "Z":
            return self._parse_type()
        if self._peek().isdigit():
            base = self._read_source_name()
            if self._peek() == "I":
                base += self._read_template_args()
            return base
        return self._parse_type()


def demangle_rtti_name(mangled_type_name: str) -> str:
    """Demangle an Itanium type_info::__type_name string (e.g. `N4fifa...E`)."""
    if not mangled_type_name:
        return ""
    s = mangled_type_name.strip()
    if s.startswith("_ZTI"):
        return f"typeinfo for {demangle_rtti_name(s[4:])}"
    if s.startswith("_ZTV"):
        return f"vtable for {demangle_rtti_name(s[4:])}"
    if s.startswith("_ZTS"):
        return f"typeinfo name for {demangle_rtti_name(s[4:])}"
    if s.startswith("_Z"):
        return demangle_symbol(s)
    if s[0] not in ("N", "P", "R", "O", "K", "F", "S", "Z", "A") and not s[0].isdigit():
        if s in _BUILTIN_TYPES:
            return _BUILTIN_TYPES[s]
        return s
    try:
        parser = _Demangler(s)
        out = parser._parse_type()
        if out and parser.pos == len(s):
            return out
        # Partial demangle is still often cleaner than raw mangled name if prefix matched
        if out and parser.pos > len(s) // 2 and "?" not in out:
            return out
    except Exception:
        pass
    return mangled_type_name


def demangle_symbol(sym: str) -> str:
    """Demangle an ELF symbol (`_Z...`) cleanly with fallback to original string."""
    if not sym or not sym.startswith("_Z"):
        return sym
    body = sym[2:]
    for prefix, label in (("TI", "typeinfo for "), ("TV", "vtable for "), ("TS", "typeinfo name for ")):
        if body.startswith(prefix):
            return label + demangle_rtti_name(body[2:])
    try:
        parser = _Demangler(body)
        base = parser._parse_encoding()
        if parser.pos == len(body):
            return base
        params: list[str] = []
        had_params = not parser._eof()
        while not parser._eof():
            params.append(parser._parse_type())
        if params == ["void"]:
            params = []
        if had_params:
            return f"{base}({', '.join(params)})"
        return base
    except Exception:
        return sym
