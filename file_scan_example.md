# Security Scan Report

**File Scanned**: `requests/utils.py`  
**Scan Time**: 2024-12-11 08:36:11

## Summary

| Severity | Count |
| -------- | ----- |
| CRITICAL | 0     |
| HIGH     | 1     |
| MEDIUM   | 4     |
| LOW      | 0     |

## Detailed Findings

### HIGH Severity

#### Line 917: Insecure Protocol Usage

```python
i.e. Link: <http:/.../front.jpeg>; rel=front; type="image/jpeg",<http://.../back.jpeg>; rel=back;type="image/jpeg"
```

**Recommendation**: Use HTTPS for all external connections to prevent data interception.

---

### MEDIUM Severity

#### Line 296: Insecure Temporary File

```python
tmp = tempfile.gettempdir()
```

**Recommendation**: Use `tempfile.mkstemp` or `tempfile.TemporaryDirectory` for secure temporary file/directory creation.

---

#### Line 300: Unsafe File Operations

```python
with atomic_open(extracted_path) as file_handler:
```

**Recommendation**: Validate and sanitize file paths before operations. Use pathlib for safer path handling.

---

#### Line 306: Unsafe File Operations

```python
def atomic_open(filename):
```

**Recommendation**: Validate and sanitize file paths before operations. Use pathlib for safer path handling.

---

#### Line 308: Insecure Temporary File

```python
tmp_descriptor, tmp_name = tempfile.mkstemp(dir=os.path.dirname(filename))
```

**Recommendation**: Use `tempfile.mkstemp` or `tempfile.TemporaryDirectory` for secure temporary file/directory creation.

---
