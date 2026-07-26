# Agent contribution rules

These rules apply to every AI-assisted change in this repository.

## Follow the contribution guide

- Read and follow [`CONTRIBUTING.md`](CONTRIBUTING.md) before changing code or
  creating commits.
- Commit titles must use `<type>(<crate/module>): <subject>`.
- Every commit must include a body explaining what changed and why.
- Keep commits reviewable and separate independent logical changes.

## Required commit trailers

- Every commit must carry the human contributor's DCO trailer:

  ```text
  Signed-off-by: Haitao Huang <haitaohuang@microsoft.com>
  ```

- Never attribute an AI agent using `Signed-off-by` or `Co-authored-by`.
- Do not add an AI `Co-authored-by` trailer.
- Declare AI assistance with:

  ```text
  Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
  ```

- Include specialized analysis tools in brackets when they materially assisted
  the change. Omit everyday development utilities such as Git, compilers,
  formatters, editors, and test runners.

Example:

```text
fix(policy): reject stale servTD collateral

Bind the accepted collateral generation to the measured policy floor so an
older correctly signed mapping cannot restore a revoked MigTD release.

Signed-off-by: Haitao Huang <haitaohuang@microsoft.com>
Assisted-by: GitHub Copilot CLI:gpt-5.6-sol [migtd-review]
```
