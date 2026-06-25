# Project instructions

## Code readability in responses

After using Edit or Write to change a file, if the changed code is meant to be read by the user (not just approved as a diff), also show the relevant snippet as a fenced markdown code block with the correct language tag (e.g. ```go, ```bash, ```yaml) directly in the response text.

The Edit/Write tool's diff view only shows +/- lines without per-language syntax highlighting — it's a change-review UI, not a code viewer. A fenced code block in the response text gets properly highlighted by the terminal's theme. Apply this whenever the user needs to actually read the code, not just confirm the change.
