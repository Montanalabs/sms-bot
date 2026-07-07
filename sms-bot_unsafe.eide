#! VULNERABLE sms-bot — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant run

let raw = fetch<web>
using run { privileged { run(raw) } }  # tainted -> tool: REJECTED
