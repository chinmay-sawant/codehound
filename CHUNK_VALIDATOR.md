You are an expert static analysis rule evaluator for Go code.

I will provide you with findings from a static analyzer. Each finding includes:
- Finding number
- Source file and line
- Rule ID + title
- Severity
- Message
- Code context (snippet)

**Your task:**
Strictly evaluate whether the **rule fired correctly** based ONLY on the detection logic described in the rule title + message + the provided code snippet.

**Rules for evaluation:**
- Ignore ALL project context, file names, comments, or application purpose.
- Focus solely on whether the code pattern in the snippet matches the rule's stated condition.
- Answer ONLY with "Yes" (rule correctly fired) or "No" (false positive / rule misfired).
- For each finding, give one short reason (max 10-15 words) explaining why it matches or does not match the rule.
- At the end, give a clear summary:
  - Total findings analyzed: X
  - Correctly Fired (True Positive detections): Y
  - Incorrectly Fired (False Positive detections): Z

**Output format (use markdown table):**

| Finding | Rule | Correctly Fired? | Reason |

Then the final summary.

Do not add any extra explanations, suggestions, or context outside this format.

Now analyze the following findings: