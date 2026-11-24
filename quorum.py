"""Signed two-of-three agreement on the next tip of a protected Git branch."""

from collections import defaultdict


QUORUM_RECORDS = {
    "quorum_root", "quorum_prepare", "quorum_promise", "quorum_choice", "quorum_accept",
}


class Ballots:
    """Reconstruct Paxos promises, accepted values, and decisions from signed records."""

    def __init__(self, root_id, records, valid_value):
        self.records = records
        self.root_id = root_id
        root = records[root_id]
        self.members = set(root["members"])
        self.prepares = {}
        self.promises = defaultdict(dict)
        self.choices = {}
        self.accepts = defaultdict(dict)
        self.accepted_ids = {}
        self.slots = defaultdict(list)
        replies = defaultdict(list)
        choices = defaultdict(list)
        accepts = defaultdict(list)
        for ident, record in records.items():
            if record["who"] not in self.members or record.get("root") != root_id:
                continue
            kind = record["kind"]
            if kind == "quorum_prepare" and record["branch"] in root["branches"]:
                self.prepares[ident] = record
                self.slots[self.slot(ident)].append(ident)
            elif kind == "quorum_promise":
                replies[record["prepare"]].append((ident, record))
            elif kind == "quorum_choice":
                choices[record["prepare"]].append((ident, record))
            elif kind == "quorum_accept":
                accepts[record["choice"]].append((ident, record))
        for prepare in sorted(self.prepares, key=self.ballot):
            owner = self.prepares[prepare]["who"]
            for ident, record in sorted(replies[prepare]):
                previous = record["accepted"]
                if previous is not None:
                    known = self.accepted_ids.get(previous)
                    if not known or known[1] != record["who"] or self.slot(known[0]) != self.slot(prepare):
                        continue
                    if self.ballot(known[0]) >= self.ballot(prepare):
                        continue
                self.promises[prepare].setdefault(record["who"], (ident, record))
            verified_promises = dict(self.promises[prepare].values())
            for choice, record in sorted(choices[prepare]):
                if record["who"] != owner or not all(item in verified_promises for item in record["promises"]):
                    continue
                votes = [verified_promises[item] for item in record["promises"]]
                previous = self.previous_choice(votes)
                if previous and self.choices[previous]["value"] != record["value"]:
                    continue
                if not valid_value(self.slot(prepare), record["value"]):
                    continue
                self.choices[choice] = record
                for ident, accepted in sorted(accepts[choice]):
                    signer = accepted["who"]
                    self.accepts[choice].setdefault(signer, ident)
                    self.accepted_ids[ident] = (prepare, signer, choice)

    def slot(self, prepare):
        record = self.prepares[prepare]
        return record["branch"], record["base"]

    def ballot(self, prepare):
        record = self.prepares[prepare]
        return record["round"], record["who"], prepare

    def previous_choice(self, votes):
        previous = [self.accepted_ids[vote["accepted"]] for vote in votes if vote["accepted"]]
        return max(previous, key=lambda item: self.ballot(item[0]))[2] if previous else None

    def tips(self):
        tips = dict(self.records[self.root_id]["branches"])
        transitions = defaultdict(set)
        for choice, signers in self.accepts.items():
            if len(signers) < 2:
                continue
            decision = self.choices[choice]
            transitions[self.slot(decision["prepare"])].add(self.records[decision["value"]["proposal"]]["head"])
        for branch, base in tips.items():
            while len(transitions[branch, base]) == 1:
                base = next(iter(transitions[branch, base]))
            tips[branch] = base
        return tips

    def next_message(self, signer, slot, value=None, retry=False):
        active = max(self.slots[slot], key=self.ballot, default=None)
        if not active or retry:
            accepted = retry and any(self.slot(item[0]) == slot for item in self.accepted_ids.values())
            if value or accepted:
                return "quorum_prepare", {"branch": slot[0], "base": slot[1],
                                          "round": self.ballot(active)[0] + 1 if active else 1}
            return None
        promises = self.promises[active]
        if signer not in promises:
            previous = [
                ident for ident, (prepare, who, _) in self.accepted_ids.items()
                if who == signer and self.slot(prepare) == slot and self.ballot(prepare) < self.ballot(active)
            ]
            accepted = max(previous, key=lambda ident: self.ballot(self.accepted_ids[ident][0]), default=None)
            return "quorum_promise", {"prepare": active, "accepted": accepted}
        choices = [ident for ident, record in self.choices.items() if record["prepare"] == active]
        if not choices:
            if self.prepares[active]["who"] == signer and len(promises) >= 2:
                pair = sorted(promises.values(), key=lambda item: item[0])[:2]
                previous = self.previous_choice([record for _, record in pair])
                if previous:
                    value = self.choices[previous]["value"]
                if value:
                    return "quorum_choice", {"prepare": active, "promises": [ident for ident, _ in pair], "value": value}
            return None
        choice = min(choices)
        if signer not in self.accepts[choice]:
            return "quorum_accept", {"choice": choice}
        return None
