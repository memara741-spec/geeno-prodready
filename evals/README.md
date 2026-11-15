# Evals

Scripts test the scanners (`python3 -m unittest discover -s tests -t tests`); these evals test whether Claude with the skill behaves well. They were authored here but not yet run in fresh sessions.

- `triggers.json`: user messages labelled `should_trigger`. Check that the skill description loads the skill for the true ones and not for the near-misses.
- `scenarios/<n>/`: `prompt.md` (the message), `fixture` (the fixture directory to use as the working directory, under `fixtures/`), `assertions.md` (what a good transcript contains and avoids).
- `rubric.md`: score each run on five dimensions.

To run one by hand: copy the fixture to a scratch folder, start a fresh session there with only `skills/prodready` installed, paste `prompt.md`, read the transcript and report against `assertions.md`, and record scores and notes in a dated file under `evals/results/`.
