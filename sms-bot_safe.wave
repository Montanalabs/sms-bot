#! SMS command bot — untrusted an SMS can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires run — the sms command bot sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant run

type Cmd = Status | Stop | Help
type Decision = Command(Cmd) | Reject

let raw = fetch<web>  # UNTRUSTED an SMS — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
using run { privileged { run(d) } }  # act on the trusted decision only
