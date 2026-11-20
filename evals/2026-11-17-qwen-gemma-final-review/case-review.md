# Inspected examples: useful advice and explanation limits

This is a qualitative inspection of selected records, not an independently
blinded accuracy study and not a score for every explanation. Publisher labels
were used for evaluation after inference; they were not supplied to the models.
Each example can be checked in `sample.jsonl`, `secondary-inputs.jsonl` and
`secondary.jsonl` by its sample ID.

## A useful warning: harrison:12719

Publisher label: `dnsteal`. Gemma retained the alert and noticed a long,
random-looking DNS query containing `customers_2020.xlsx`. The quoted query was
checked and occurs verbatim in the recorded event. Its suggestion to investigate
possible data theft is tied to a concrete clue, rather than merely the `.biz`
ending of the domain name. The record alone still does not establish the whole
attack sequence or prove that data theft succeeded.

## Correct copied fields, questionable interpretation: fox:12977

Publisher label: `-` (no attack annotation). Gemma retained the alert, described
port 41262 as a non-standard service port and advised checking the application
listening there. Its own challenge pass accepted the assessment.

The original security report shows a TCP packet from port 443 to port 41262.
A high-numbered destination port may be a client receiving a reply; that field
alone does not establish a listening application or a suspicious service.
Gemma's advice should have kept this possibility explicit. The standalone
normalized fields omit the source port on this older text-wrapped alert even
though the original message preserves it. That is an evidence-extraction gap to
fix and test, alongside the model's interpretation.

This illustrates why exact fact checks are insufficient: the numbers can be
copied correctly while the story built around them is misleading. It is an L2
explanation limitation, not an attack suppression by the prefilter.

## A retained attack record with an overstated reason: fox:447150

Publisher label: `attacker_change_user`. Gemma retained the warning. The source
says systemd opened a session for `phopkins` by `uid=0`. Gemma described this as a
high-risk indicator of possible privilege escalation.

`uid=0` means an administrator-level process. Its presence in a system-managed
session log does not, by itself, demonstrate that the person gained new powers
or acted without authorization. Keeping this attack-annotated record flagged
matches the label, but the explanation needs surrounding login/process activity.
The model should distinguish a recorded privileged process from a demonstrated
unauthorized privilege change. Its challenge pass also accepted this explanation.

## Routine-looking did not mean suppressed: wheeler:2913

Publisher label: `-`. Gemma called the DNS query for
`intranet.flores.wheeler.biz` routine-looking and reported confidence 0.9, but
its explicit decision was still `escalate`. The challenge accepted it. The code
did not overturn a suppression proposal: none was made. An outlook description
and a final decision are separate fields, and this case illustrates why the
actual decision must be measured rather than inferred from friendly wording.

## What these examples suggest testing next

- Preserve source and destination ports from every supported alert wrapper,
  including older Suricata text inside Wazuh records.
- Check network direction and client/server roles before inferring a listening
  service from a port number.
- Supply and test chronological login/process context before treating system
  account activity as proof of an unauthorized privilege change.
- Independently score explanations as well as final alert decisions. A useful
  final flag can coexist with a weak reason, and a self-challenge can agree with
  an unsupported interpretation.
