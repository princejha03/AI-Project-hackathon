# TrueSignal — Demo Video Script (~6-7 minutes)

**Format:** screen share + you talking. `**[SCREEN: ...]**` = what to click. Everything else = what to say. Keep it casual, like you're showing a friend, not presenting a paper.

**Before you record:**
- Run `python run.py`. It opens the browser at `http://127.0.0.1:5000` by itself.
- Login: `admin` / `checkmarx`
- The demo project we'll use: **WebShop**

---

## 0:00 – 0:35 — The problem

**[SCREEN: blank tab]**

> Quick scenario. You scan your code for security bugs, and you get a big list of findings. Most of them are false alarms — stuff your team already knows is safe, because it goes through some cleanup code you wrote. The scanner just doesn't know that.

> So someone checks each one, says "yeah this one's fine," and moves on. Next scan? Same false alarm shows up again. Nobody taught the scanner anything.

> And sometimes it's worse — a real bug is completely invisible, because the scanner doesn't realize one of your functions is quietly pulling in user input.

> That's what I built TrueSignal for. It learns from how your team already reviews findings, and turns that into permanent rules the scanner remembers.

---

## 0:35 – 1:05 — The important part first

**[SCREEN: open http://127.0.0.1:5000]**

> One thing before I show you anything: the AI never gets the final say here. Every guess it makes has to pass a check first. If it doesn't pass, a real person has to look at it. And anything that does go through gets logged, and you can undo it in one click.

> So it's not "let the AI run the scanner." It's "AI suggests, a rule checks it, a human can always override it."

---

## 1:05 – 1:35 — How it works, fast

> Four steps. It reads your code and flags interesting functions. It asks an AI "is this safe cleanup code, or something risky?" That guess gets double-checked — a cleanup function only auto-approves if the AI's confident *and* your team already has history backing it up. Then it turns approved guesses into actual scanner rules, and re-scans to show you what changed.

> Let's just look at it.

---

## 1:35 – 4:30 — Live demo

**[SCREEN: log in as admin]**

> Logging in. There's also a lighter account for regular team members — they can review findings but can't change settings or undo things. I'll show that later.

**[SCREEN: dashboard]**

> This is the dashboard. All your projects, live numbers, nothing cached.

**[SCREEN: click into WebShop → Findings & audit]**

> Let's open one project — a SQL injection example. Here's the findings list. Eight findings, all going through this one homemade cleanup function the scanner doesn't trust.

**[SCREEN: click "Run TrueSignal analysis"]**

> Let's run the analysis. Nothing gets changed yet — this is just proposals.

**[SCREEN: the review screen]**

> Here it is: "I think this function is a safe cleanup step, here's why" — and next to it, how many people already dismissed findings pointing at it. That's the proof it needs before it can auto-approve.

> And here's a second one — a wrapper function that quietly pulls in user input. Right now the scanner has no idea. Whatever bug is hiding behind it is invisible today.

**[SCREEN: select both, confirm]**

> I'll approve both.

**[SCREEN: results screen]**

> And here's the payoff. Seven findings just got cleared as safe — real false alarms, gone for good. And a brand new critical finding just appeared — that's the bug that was hiding behind that wrapper function. One step: fewer false alarms, and a real bug that was invisible before.

**[SCREEN: ledger]**

> Every change is logged here. If one ever turns out wrong, you roll it back with one click, and it undoes exactly that.

---

## 4:30 – 5:15 — Why you can trust it

> Quick note on why this is safe. Cleanup functions get the strictest check, on purpose — because if the tool is wrong here, it just told the scanner to ignore a real bug. So it needs both AI confidence *and* real human backup, not just one.

> There's also a tiny feedback system — not some self-learning AI, just simple numbers. Approvals nudge a function's trust score up a little, getting rolled back nudges it down more, and the whole thing is capped so it can never swing wildly. You can see the exact numbers on screen the whole time.

---

## 5:15 – 6:00 — A couple more things, quickly

**[SCREEN: quickly show the Activity page, then log in as appsec and get blocked from it]**

> A few more things I'll go through fast. It can spot when a cleanup function in one project looks like one already proven safe in a totally different project, and suggest it there too — no extra AI needed for that, just comparing the code. There's a team dashboard, admin-only — and I mean actually locked down, not just hidden — watch, I log in as a regular user and try to visit it directly... blocked. And there's a review queue for teaching a locally-run AI model from its own mistakes, with a human always signing off before anything's used.

---

## 6:00 – 6:30 — Wrap up

**[SCREEN: back to dashboard]**

> So — TrueSignal takes the review work your team's already doing and makes it permanent. Stuff you've cleared once stays cleared. Bugs hiding behind functions the scanner didn't understand get a chance to show up. And every step of it needs a real check or a real person before anything actually changes.

> Thanks for watching.

---

## If you need it even shorter (~5 min)

Cut section "5:15 – 6:00" entirely — just say one line instead: *"There's more under the hood — cross-project learning, an admin dashboard, a way to retrain the AI from its mistakes — happy to go deeper if you're curious."* Then go straight to the wrap-up.

## Quick answers if someone asks a hard question

- **"What stops the AI from just being confidently wrong?"** → It's never trusted alone — cleanup functions need real human history behind them too, not just AI confidence.
- **"Is the learning part training an AI model?"** → No — just small numbers nudging up or down, capped, fully visible, resettable.
- **"What if it crashes while saving?"** → It always saves to a backup file first, then swaps it in — so a crash can't corrupt your history.
- **"Does this work on a real, huge codebase?"** → Being honest — right now it reads code with pattern-matching, not a full parser. That's the known next step.
