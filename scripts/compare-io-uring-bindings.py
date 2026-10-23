#!/usr/bin/env python3
"""Emit ARM compile-time layout checks for Cargo's selected io-uring bindings."""
import json
import re
import sys
from pathlib import Path

metadata = json.loads(Path(sys.argv[1]).read_text())
root = next(node for node in metadata["resolve"]["nodes"]
            if node["id"] == metadata["resolve"]["root"])
dependency = next(dep["pkg"] for dep in root["deps"] if dep["name"] == "io_uring")
package = next(pkg for pkg in metadata["packages"] if pkg["id"] == dependency)
if package["version"] != "0.7.15":
    sys.exit("Review the ABI checker when updating io-uring")
source = Path(package["manifest_path"]).parent / "src/sys"
# ARM selects this fallback in io-uring 0.7.15's sys.rs.
if not re.search(r'else\s*\{\s*include!\("sys_x86_64.rs"\);\s*\}',
                 (source / "sys.rs").read_text()):
    sys.exit("io-uring's unsupported-architecture binding selection changed")
selected = source / "sys_x86_64.rs"
generated = Path(sys.argv[2]).resolve()


def records(path):
    """Read bindgen's named structs/unions; reject unrecognized field syntax."""
    result = {}
    for name, body in re.findall(r"pub (?:struct|union) (\w+) \{\n(.*?)^\}",
                                 path.read_text(), re.M | re.S):
        fields = []
        for line in body.splitlines():
            if line.strip().startswith("pub "):
                match = re.fullmatch(r"\s*pub (\w+): (.+),", line)
                if not match:
                    sys.exit(f"Unsupported bindgen field: {line}")
                fields.append(match.groups())
        result[name] = fields
    return result


def field_paths(types, name, prefix=(), key=()):
    result = {}
    for field, kind in types[name]:
        path = prefix + (field,)
        # Anonymous union numbering can differ across kernel header versions.
        canonical = key if field.startswith("__bindgen_anon_") else key + (field,)
        if not field.startswith("__bindgen_anon_"):
            result[canonical] = ".".join(path)
        if kind in types:
            result.update(field_paths(types, kind, path, canonical))
    return result


selected_types, arm_types = records(selected), records(generated)
types = ("io_sqring_offsets", "io_cqring_offsets", "io_uring_params",
         "io_uring_sqe", "io_uring_cqe", "io_uring_rsrc_update",
         "io_uring_rsrc_update2", "io_uring_files_update",
         "io_uring_getevents_arg", "__kernel_timespec")
checks = ["#![no_std]", "#![allow(dead_code, non_camel_case_types, non_upper_case_globals)]",
          f"mod selected {{ use core::ffi as libc; include!({json.dumps(str(selected))}); }}",
          f"mod arm {{ include!({json.dumps(str(generated))}); }}",
          "const fn width<T, F>(_: fn(*const T) -> *const F) -> usize { core::mem::size_of::<F>() }"]
for name in types:
    for property in ("size_of", "align_of"):
        checks.append(f'const _: () = assert!(core::mem::{property}::<selected::{name}>() == '
                      f'core::mem::{property}::<arm::{name}>(), "{name} {property}");')
    selected_fields = field_paths(selected_types, name)
    arm_fields = field_paths(arm_types, name)
    for key, arm_field in arm_fields.items():
        # Reserved padding can be renamed/reused by newer kernel headers.
        if any(part.startswith(("pad", "__pad", "resv", "__resv")) for part in key):
            continue
        if key not in selected_fields:
            sys.exit(f"ARM header field missing from selected bindings: {name}.{'.'.join(key)}")
        selected_field = selected_fields[key]
        label = f"{name}.{'.'.join(key)}"
        checks.append(f'const _: () = assert!(core::mem::offset_of!(selected::{name}, {selected_field}) == '
                      f'core::mem::offset_of!(arm::{name}, {arm_field}), "{label} offset");')
        checks.append(f'const _: () = assert!(width(|p: *const selected::{name}| unsafe {{ '
                      f'core::ptr::addr_of!((*p).{selected_field}) }}) == '
                      f'width(|p: *const arm::{name}| unsafe {{ core::ptr::addr_of!((*p).{arm_field}) }}), '
                      f'"{label} width");')
Path(sys.argv[3]).write_text("\n".join(checks) + "\n")
