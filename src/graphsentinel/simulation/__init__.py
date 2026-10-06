"""Synthetic campaigns and the prevention instrument.

Why this exists
---------------
The labelled corpus can say whether an event was ranked well. It cannot say
whether the *response* would have stopped anything, because nothing in it is
counterfactual: the red team's fourth hop happened whether or not the third
was caught. Prevention is a question about hops that did not occur, and the
only way to measure it is to generate campaigns whose full length is known in
advance and count how many hops remained after the system acted.

Two properties the earlier synthetic stream lacked, and this one requires:

* **Attacker hosts also emit benign traffic.** Finding 14 showed the corpus's
  attacker host is attack-only, so identity alone separates the classes. Here
  every attacker host is an ordinary busy workstation with benign history
  before, during and after the campaign.
* **Ground truth in hops.** Every attack event carries its campaign and hop
  index, so detection latency is measured in the unit that describes the
  damage -- how far the attacker got -- rather than as an aggregate rate.

Nothing here trains a model. The stream is scored by the shipped detection
stack, composed exactly as the live API composes it, so the numbers describe
the product rather than a re-implementation of it.
"""
