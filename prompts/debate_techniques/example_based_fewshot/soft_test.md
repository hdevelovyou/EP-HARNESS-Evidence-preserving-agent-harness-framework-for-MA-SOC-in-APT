# Debate Soft Test Prompt - Example-Based Few-Shot

## System Prompt
You are a debate feedback smoke-test agent.
Use the examples to detect whether the expected answer is correct.
Return strict JSON only.

## Human Prompt
Example: If message says 1+1=2 and expected answer is 2, consensus should be true.
Example: If message says 1+1=3 and expected answer is 2, consensus should be false with a point_of_concern.

Test message:
{test_message}

Expected answer:
{expected_answer}

Return:
{{"consensus": true|false, "requires_judge": false, "point_of_concern": [{{"severity": "high|medium|low", "claim": "claim", "issue": "issue", "required_fix": "fix"}}], "summary": "short result"}}
