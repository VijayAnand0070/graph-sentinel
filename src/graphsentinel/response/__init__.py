"""Execution of response actions against directory, network and endpoint systems.

The detection layer decides *what* should happen (``detection/response.py``
partitions a plan into auto-executable and approval-required actions). This
package is *how* it happens, and it exists to keep three properties true at
the only place they can be enforced:

* **Nothing runs unless armed.** Every connector plans a concrete, auditable
  command; the default backend records the plan and performs nothing. A
  deployment opts into execution explicitly, per backend.
* **The plan's partition is binding.** An action the plan marked as needing
  approval is not executed without an approval for that alert and that
  action, and an irreversible action is never executed without one regardless
  of what any plan says -- the action catalogue is the authority.
* **Every dispatch leaves a record** stating what was asked, what was planned,
  what ran, whether it can be reverted, and how -- whether or not it ran.

Validation status
-----------------
The command plans are correct by specification: they are the documented
commands for each operation. They have not been run against a live directory
in this environment, which had no lab domain to run them against. That is why
the dry-run backend is the default and the executing backends are constructed
only on purpose.
"""
