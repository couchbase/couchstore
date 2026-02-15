# AGENTS.md — couchstore Repository Guide

Repository (mirror): https://github.com/couchbase/couchstore
Primary code review system: https://review.couchbase.org

---

## 📌 Purpose

This document defines expectations for:

- Automated coding agents
- Human contributors
- Reviewers

Couchstore uses Gerrit (review.couchbase.org) for all change
submission, validation, and approval.

GitHub is a mirror only. Do NOT open GitHub Pull Requests.

---

## 🧱 Repository Overview

Couchstore is a C++ storage file library used within
Couchbase Server.

The repository includes:

- Core engine implementation (`src/`)
- Public headers (`include/`)
- File format documentation (`file_format.md`,
  `view_format.md`, etc.)
- Unit tests (`tests/`)
- CMake-based build system

On-disk compatibility must be preserved unless a change
explicitly documents and justifies a format update.

---

## 🚦 Authoritative Contribution Workflow

All changes must be submitted via:

    https://review.couchbase.org

### Standard Flow

1. Sync with latest target branch (typically `master`)
2. Create a local topic branch
3. Make atomic, focused commits
4. Run local build and tests
5. Push to Gerrit (substitute master for correct branch):

       git push origin HEAD:refs/for/master

6. CI validation runs automatically
7. Review feedback is asynchronous

---

## Building

- couchstore is built as part of couchbase-server
- https://github.com/couchbase/tlm/README.md describes how to configure and build
- tlm must exist as a local checkout alongside couchstore

---

## ⏳ Agents Must Not Wait for Review

Code review and approval may take hours or days.

Automated agents must:

- Submit the change to Gerrit
- Ensure local tests pass before submission
- Provide a clear summary of work performed
- Conclude their task without waiting for approval

Agents must NOT:

- Block waiting for review completion
- Poll Gerrit for approval status
- Attempt to self-approve changes
- Attempt to bypass CI validation

Review is handled asynchronously by humans.

---

## 🧠 Expectations for Automated Agents

### Before Coding

- Read relevant file format documentation
- Inspect similar existing implementations
- Understand storage compatibility impact

### When Generating Code

- Follow existing C++ style and patterns
- Avoid stylistic-only changes
- Keep diffs minimal and focused
- Add or update unit tests for behavioral changes
- Avoid introducing new dependencies
- Do not change file format behavior silently

---

## 📝 Commit Message Requirements

All commit messages must:

- Start with: `MB-XXXXX: Short summary`
- Be wrapped at **72 characters per line**
- Include a clear explanation of:
  - What changed
  - Why it changed
  - Risk or compatibility impact

Example:

MB-12345: Fix incorrect header length validation

Correct off-by-one error in couchstore_open_header which
could allow malformed headers to pass validation. Adds
regression test covering truncated header cases.


### Change-Id Handling

Do NOT manually add or generate a `Change-Id`.

A local Gerrit commit-msg hook is expected to already be
installed and will automatically append the required
`Change-Id` footer when the commit is created or amended.

Agents must not fabricate or modify the Change-Id.

---

## 🧪 Testing Requirements

All functional changes must include:

- New or updated unit tests
- Passing test suite locally
- No unintended regression in file format compatibility

File format changes require documentation updates.

---

## 📐 Code Standards

Language: **C++ (up to C++20 supported)**

Guidelines:

- Prefer modern C++ where appropriate (C++17/20 features
  are supported)
- Use RAII, smart pointers, and standard library facilities
  where they improve safety and clarity
- Structured bindings, `std::optional`, `std::variant`,
  `constexpr`, and other modern features are acceptable
- Match the surrounding style within the modified module
- It is acceptable to use older constructs if required for
  consistency with the existing code in that area
- Avoid unnecessary large-scale modernization in unrelated
  code
- Maintain cross-platform compatibility

Style consistency within a patch is more important than
using the newest available language feature.

---

## 📂 Documentation Rules

If a change impacts:

- On-disk file format
- Public APIs
- Storage behavior

Then update:

- `file_format.md`
- `view_format.md`
- Relevant headers and inline comments

Documentation drift is not acceptable.

---

## 🔄 Patchset Iteration

When addressing review feedback:

- Amend the existing commit
- Do not create unrelated commits
- Preserve the automatically generated Change-Id
- Keep history clean and atomic

---

## 🚨 Safety Rules

Agents must not:

- Change file format silently
- Break backward compatibility unintentionally
- Reformat large areas of code
- Submit speculative refactors
- Bypass Gerrit workflow

---

## 📎 References

Gerrit: https://review.couchbase.org
GitHub mirror: https://github.com/couchbase/couchstore


