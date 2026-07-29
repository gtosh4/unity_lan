# GUI crate

Unprivileged iced desktop app; drives the engine over its control socket (`common::control`). Root
`CLAUDE.md` has the project-wide rules.

**GUI screenshots are docs.** When a change alters what the app looks like, regenerate them with
`scripts/readme-demo.sh` (fake-engine fixtures + scripted tour + screencast): it writes
`assets/demo.gif`, `demo-peers.{webm,mp4}` (site hero), `peers.png`, `services.png`, `networks.png`.
The script needs an interactive Wayland desktop with a screencast portal — not headless-able, so the
user runs it themselves via the `! <cmd>` prefix; ask rather than attempting.

The Services tab is the only place sharing lives: every exposure carries a name (an unnamed one is
`port-<number>`, assigned when the firewall loads it), so there is no second list of nameless ports
to keep in step.

Keep the fixtures in `examples/fake-engine.rs` representative of the feature shown, else regenerated
stills won't demonstrate it. Its `demo_script` is the tour the recording follows, and the still marks
in `readme-demo.sh` are cut from the middle of each dwell — move a step and you must move them too, or
a screenshot lands mid-transition. Those fixtures are also the only way to exercise the GUI without a
privileged engine.
